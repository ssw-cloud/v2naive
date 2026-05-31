package proxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/juju/ratelimit"
	log "github.com/sirupsen/logrus"
	"github.com/ssw-cloud/v2naive/internal/limiter"
	panel "github.com/ssw-cloud/v2naive/internal/panel"
)

var errDeviceLimit = errors.New("device limit reached")

type Server struct {
	node         *panel.NodeInfo
	limiter      *limiter.Limiter
	usersMu      sync.RWMutex
	users        map[string]panel.UserInfo
	statsMu      sync.RWMutex
	stats        map[string]*trafficCounter
	httpServer   *http.Server
	listener     net.Listener
	transport    *http.Transport
	shutdownOnce sync.Once
}

type trafficCounter struct {
	uid  int
	mu   sync.Mutex
	up   int64
	down int64
}

func New(node *panel.NodeInfo, users []panel.UserInfo, alive map[int]int) *Server {
	s := &Server{
		node:    node,
		users:   make(map[string]panel.UserInfo, len(users)),
		stats:   make(map[string]*trafficCounter, len(users)),
		limiter: limiter.New(users, alive),
		transport: &http.Transport{
			Proxy:               nil,
			TLSHandshakeTimeout: 15 * time.Second,
			IdleConnTimeout:     60 * time.Second,
			DisableCompression:  false,
		},
	}
	s.replaceUsers(users)
	return s
}

func (s *Server) replaceUsers(users []panel.UserInfo) {
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	for _, user := range users {
		s.users[user.Uuid] = user
	}
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	for _, user := range users {
		if stat, ok := s.stats[user.Uuid]; ok {
			stat.setUID(user.Id)
		} else {
			s.stats[user.Uuid] = &trafficCounter{uid: user.Id}
		}
	}
}

func (s *Server) Start() error {
	if s.node.CertInfo == nil {
		return fmt.Errorf("cert info is nil")
	}
	cert, err := tls.LoadX509KeyPair(s.node.CertInfo.CertFile, s.node.CertInfo.KeyFile)
	if err != nil {
		return fmt.Errorf("load cert pair error: %w", err)
	}

	addr := net.JoinHostPort(s.node.ListenIP, strconv.Itoa(s.node.ServerPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen error: %w", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	tlsListener := tls.NewListener(ln, tlsConfig)

	s.listener = tlsListener
	s.httpServer = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		if err := s.httpServer.Serve(tlsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.WithError(err).Error("v2naive serve failed")
		}
	}()
	log.WithField("addr", addr).Info("v2naive listener started")
	return nil
}

func (s *Server) Close() error {
	var err error
	s.shutdownOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if s.httpServer != nil {
			err = s.httpServer.Shutdown(ctx)
		}
		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.transport.CloseIdleConnections()
	})
	return err
}

func (s *Server) SetAliveList(alive map[int]int) {
	s.limiter.SetAliveList(alive)
}

func (s *Server) UpdateUsers(added, deleted, modified, full []panel.UserInfo) {
	s.usersMu.Lock()
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	defer s.usersMu.Unlock()
	for _, user := range deleted {
		delete(s.users, user.Uuid)
		if stat, ok := s.stats[user.Uuid]; ok {
			stat.setUID(user.Id)
			if !stat.hasPending() {
				delete(s.stats, user.Uuid)
			}
		}
	}
	for _, user := range added {
		s.users[user.Uuid] = user
		if _, ok := s.stats[user.Uuid]; !ok {
			s.stats[user.Uuid] = &trafficCounter{uid: user.Id}
		}
	}
	for _, user := range modified {
		s.users[user.Uuid] = user
		if stat, ok := s.stats[user.Uuid]; ok {
			stat.setUID(user.Id)
		} else {
			s.stats[user.Uuid] = &trafficCounter{uid: user.Id}
		}
	}
	if full != nil {
		for _, user := range full {
			if stat, ok := s.stats[user.Uuid]; ok {
				stat.setUID(user.Id)
			} else {
				s.stats[user.Uuid] = &trafficCounter{uid: user.Id}
			}
		}
	}
	s.limiter.UpdateUsers(added, deleted, modified)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user, bucket, err := s.authenticate(r)
	if err != nil {
		if errors.Is(err, errDeviceLimit) {
			http.Error(w, "device limit reached", http.StatusForbidden)
		} else {
			writeProxyAuthRequired(w)
		}
		return
	}
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r, user, bucket)
		return
	}
	s.handleHTTP(w, r, user, bucket)
}

func (s *Server) authenticate(r *http.Request) (panel.UserInfo, *ratelimit.Bucket, error) {
	authHeader := r.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		authHeader = r.Header.Get("Authorization")
	}
	username, password, ok := parseBasicAuth(authHeader)
	if !ok {
		return panel.UserInfo{}, nil, fmt.Errorf("missing auth")
	}

	s.usersMu.RLock()
	user, exists := s.users[username]
	s.usersMu.RUnlock()
	if !exists || password != user.Uuid {
		return panel.UserInfo{}, nil, fmt.Errorf("invalid auth")
	}

	bucket, reject := s.limiter.CheckLimit(user.Uuid, clientIP(r.RemoteAddr))
	if reject {
		return panel.UserInfo{}, nil, errDeviceLimit
	}
	return user, bucket, nil
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request, user panel.UserInfo, bucket *ratelimit.Bucket) {
	targetAddr := canonicalAddr(r.Host, "443")
	upstream, err := net.DialTimeout("tcp", targetAddr, 15*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	if r.ProtoMajor == 1 {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			upstream.Close()
			http.Error(w, "hijack not supported", http.StatusInternalServerError)
			return
		}
		clientConn, bufrw, err := hijacker.Hijack()
		if err != nil {
			upstream.Close()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			clientConn.Close()
			upstream.Close()
			return
		}
		if buffered := bufrw.Reader.Buffered(); buffered > 0 {
			_, _ = copyWithAccount(upstream, io.LimitReader(bufrw.Reader, int64(buffered)), s.getCounter(user.Uuid), bucket, true)
		}
		s.pipeTunnel(clientConn, upstream, s.getCounter(user.Uuid), bucket)
		return
	}

	controller := http.NewResponseController(w)
	_ = controller.EnableFullDuplex()
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	counter := s.getCounter(user.Uuid)
	errCh := make(chan error, 2)

	go func() {
		_, copyErr := copyWithAccount(upstream, r.Body, counter, bucket, true)
		if tcpConn, ok := upstream.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		errCh <- copyErr
	}()
	go func() {
		_, copyErr := copyWithAccount(flushWriter{ResponseWriter: w}, upstream, counter, bucket, false)
		errCh <- copyErr
	}()

	<-errCh
	_ = upstream.Close()
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request, user panel.UserInfo, bucket *ratelimit.Bucket) {
	outReq := new(http.Request)
	*outReq = *r
	if outReq.URL == nil {
		http.Error(w, "invalid url", http.StatusBadRequest)
		return
	}
	if outReq.URL.Scheme == "" {
		outReq.URL = &url.URL{
			Scheme:   "http",
			Host:     outReq.Host,
			Path:     outReq.URL.Path,
			RawQuery: outReq.URL.RawQuery,
		}
	}
	outReq.RequestURI = ""
	outReq.Header = cloneHeader(r.Header)
	stripProxyHeaders(outReq.Header)
	if r.Body != nil {
		outReq.Body = io.NopCloser(&countingReader{
			reader:  r.Body,
			counter: s.getCounter(user.Uuid),
			bucket:  bucket,
			upload:  true,
		})
	}

	resp, err := s.transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = copyWithAccount(flushWriter{ResponseWriter: w}, resp.Body, s.getCounter(user.Uuid), bucket, false)
}

func (s *Server) pipeTunnel(clientConn net.Conn, upstream net.Conn, counter *trafficCounter, bucket *ratelimit.Bucket) {
	defer clientConn.Close()
	defer upstream.Close()

	errCh := make(chan struct{}, 2)
	go func() {
		_, _ = copyWithAccount(upstream, clientConn, counter, bucket, true)
		if tcpConn, ok := upstream.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		errCh <- struct{}{}
	}()
	go func() {
		_, _ = copyWithAccount(clientConn, upstream, counter, bucket, false)
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		errCh <- struct{}{}
	}()
	<-errCh
}

func (s *Server) getCounter(uuid string) *trafficCounter {
	s.statsMu.RLock()
	counter, ok := s.stats[uuid]
	s.statsMu.RUnlock()
	if ok {
		return counter
	}

	s.usersMu.RLock()
	user, userOK := s.users[uuid]
	s.usersMu.RUnlock()

	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	if counter, ok = s.stats[uuid]; ok {
		return counter
	}
	counter = &trafficCounter{}
	if userOK {
		counter.uid = user.Id
	}
	s.stats[uuid] = counter
	return counter
}

func (t *trafficCounter) addUpload(n int64) {
	if n <= 0 {
		return
	}
	t.mu.Lock()
	t.up += n
	t.mu.Unlock()
}

func (t *trafficCounter) addDownload(n int64) {
	if n <= 0 {
		return
	}
	t.mu.Lock()
	t.down += n
	t.mu.Unlock()
}

func (t *trafficCounter) setUID(uid int) {
	t.mu.Lock()
	t.uid = uid
	t.mu.Unlock()
}

func (t *trafficCounter) snapshotIfAbove(minTraffic int) (panel.UserTraffic, bool) {
	threshold := int64(minTraffic) * 1000
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.up+t.down <= threshold {
		return panel.UserTraffic{}, false
	}
	data := panel.UserTraffic{
		UID:      t.uid,
		Upload:   t.up,
		Download: t.down,
	}
	return data, true
}

func (t *trafficCounter) confirm(reported panel.UserTraffic) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.up = subtractReported(t.up, reported.Upload)
	t.down = subtractReported(t.down, reported.Download)
}

func (t *trafficCounter) hasPending() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.up > 0 || t.down > 0
}

func (t *trafficCounter) currentUID() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.uid
}

func subtractReported(current, reported int64) int64 {
	if reported <= 0 {
		return current
	}
	if current <= reported {
		return 0
	}
	return current - reported
}

func (s *Server) GetUserTrafficSlice(minTraffic int) []panel.UserTraffic {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()
	traffic := make([]panel.UserTraffic, 0, len(s.stats))
	for uuid, counter := range s.stats {
		if snapshot, ok := counter.snapshotIfAbove(minTraffic); ok {
			snapshot.UUID = uuid
			traffic = append(traffic, snapshot)
		}
	}
	return traffic
}

func (s *Server) ConfirmUserTraffic(reported []panel.UserTraffic) {
	if len(reported) == 0 {
		return
	}
	byUUID, byUID := indexReportedTraffic(reported)
	activeUsers := s.activeUserUUIDs()

	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	for uuid, counter := range s.stats {
		if traffic, ok := byUUID[uuid]; ok {
			counter.confirm(traffic)
		} else if traffic, ok := byUID[counter.currentUID()]; ok {
			counter.confirm(traffic)
		}
		if _, active := activeUsers[uuid]; !active && !counter.hasPending() {
			delete(s.stats, uuid)
		}
	}
}

func (s *Server) activeUserUUIDs() map[string]struct{} {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	active := make(map[string]struct{}, len(s.users))
	for uuid := range s.users {
		active[uuid] = struct{}{}
	}
	return active
}

func indexReportedTraffic(reported []panel.UserTraffic) (map[string]panel.UserTraffic, map[int]panel.UserTraffic) {
	byUUID := make(map[string]panel.UserTraffic, len(reported))
	byUID := make(map[int]panel.UserTraffic, len(reported))
	for _, traffic := range reported {
		if traffic.UUID != "" {
			merged := byUUID[traffic.UUID]
			merged.UID = traffic.UID
			merged.UUID = traffic.UUID
			merged.Upload += traffic.Upload
			merged.Download += traffic.Download
			byUUID[traffic.UUID] = merged
			continue
		}
		merged := byUID[traffic.UID]
		merged.UID = traffic.UID
		merged.Upload += traffic.Upload
		merged.Download += traffic.Download
		byUID[traffic.UID] = merged
	}
	return byUUID, byUID
}

func (s *Server) GetOnlineDevice() []panel.OnlineUser {
	return s.limiter.GetOnlineDevice()
}

type countingReader struct {
	reader  io.Reader
	counter *trafficCounter
	bucket  *ratelimit.Bucket
	upload  bool
}

func (r *countingReader) Read(p []byte) (int, error) {
	if r.bucket != nil {
		r.bucket.Wait(int64(len(p)))
	}
	n, err := r.reader.Read(p)
	if r.upload {
		r.counter.addUpload(int64(n))
	} else {
		r.counter.addDownload(int64(n))
	}
	return n, err
}

type limitedWriter struct {
	writer io.Writer
	bucket *ratelimit.Bucket
}

func (w limitedWriter) Write(p []byte) (int, error) {
	if w.bucket != nil {
		w.bucket.Wait(int64(len(p)))
	}
	return w.writer.Write(p)
}

type flushWriter struct {
	http.ResponseWriter
}

func (w flushWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
	return n, err
}

func copyWithAccount(dst io.Writer, src io.Reader, counter *trafficCounter, bucket *ratelimit.Bucket, upload bool) (int64, error) {
	writer := dst
	if bucket != nil {
		writer = limitedWriter{writer: dst, bucket: bucket}
	}
	n, err := io.Copy(writer, src)
	if upload {
		counter.addUpload(n)
	} else {
		counter.addDownload(n)
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return n, nil
	}
	return n, err
}

func parseBasicAuth(auth string) (string, string, bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func canonicalAddr(hostport, defaultPort string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return ":" + defaultPort
	}
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	return net.JoinHostPort(hostport, defaultPort)
}

func writeProxyAuthRequired(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
	http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
}

func stripProxyHeaders(h http.Header) {
	for _, key := range []string{
		"Proxy-Authorization",
		"Proxy-Connection",
		"Connection",
		"Keep-Alive",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		h.Del(key)
	}
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, values := range h {
		copied := make([]string, len(values))
		copy(copied, values)
		out[k] = copied
	}
	return out
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		canonicalKey := textproto.CanonicalMIMEHeaderKey(key)
		for _, value := range values {
			dst.Add(canonicalKey, value)
		}
	}
}
