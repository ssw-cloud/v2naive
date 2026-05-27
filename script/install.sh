#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/ssw-cloud/v2naive.git}"
REPO_BRANCH="${REPO_BRANCH:-main}"
REPO_SLUG="${REPO_SLUG:-ssw-cloud/v2naive}"
INSTALL_DIR="${INSTALL_DIR:-/opt/v2naive}"
SRC_DIR="${SRC_DIR:-${INSTALL_DIR}/src}"
BIN_PATH="${BIN_PATH:-${INSTALL_DIR}/v2naive}"
CADDY_BIN_PATH="${CADDY_BIN_PATH:-${INSTALL_DIR}/caddy}"
CONFIG_DIR="${CONFIG_DIR:-/etc/v2naive}"
CONFIG_PATH="${CONFIG_PATH:-${CONFIG_DIR}/config.yml}"
SERVICE_NAME="${SERVICE_NAME:-v2naive}"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
LOG_DIR="${LOG_DIR:-/var/log/v2naive}"
LOGROTATE_PATH="/etc/logrotate.d/${SERVICE_NAME}"
STATE_DIR="${STATE_DIR:-/var/lib/v2naive}"
RELEASE_VERSION="${RELEASE_VERSION:-latest}"
GO_VERSION="${GO_VERSION:-1.25.6}"
MIN_GO_VERSION="${MIN_GO_VERSION:-1.24.0}"
GO_BIN=""
BUILD_FROM_SOURCE=0
ENGINE="${ENGINE:-caddy}"
UPGRADE_ONLY=0

API_HOST=""
NODE_ID=""
API_KEY=""

usage() {
  cat <<'EOF'
Usage:
  bash install.sh --api-host https://panel.example.com --node-id 1 --api-key your-token
  bash install.sh --upgrade

Optional flags:
  --upgrade
  --version TAG
  --engine caddy|legacy
  --build-from-source
  --repo-url URL
  --repo-branch BRANCH
  --install-dir PATH
  --config-path PATH
  --service-name NAME
  --go-version VERSION
EOF
}

log() {
  echo "[v2naive] $*"
}

fail() {
  echo "[v2naive] ERROR: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

version_ge() {
  local current="$1"
  local minimum="$2"
  [[ "$(printf '%s\n%s\n' "$minimum" "$current" | sort -V | head -n1)" == "$minimum" ]]
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --api-host)
        API_HOST="${2:-}"
        shift 2
        ;;
      --node-id)
        NODE_ID="${2:-}"
        shift 2
        ;;
      --api-key)
        API_KEY="${2:-}"
        shift 2
        ;;
      --repo-url)
        REPO_URL="${2:-}"
        shift 2
        ;;
      --version)
        RELEASE_VERSION="${2:-}"
        shift 2
        ;;
      --build-from-source)
        BUILD_FROM_SOURCE=1
        shift 1
        ;;
      --upgrade)
        UPGRADE_ONLY=1
        shift 1
        ;;
      --engine)
        ENGINE="${2:-}"
        shift 2
        ;;
      --repo-branch)
        REPO_BRANCH="${2:-}"
        shift 2
        ;;
      --install-dir)
        INSTALL_DIR="${2:-}"
        SRC_DIR="${INSTALL_DIR}/src"
        BIN_PATH="${INSTALL_DIR}/v2naive"
        CADDY_BIN_PATH="${INSTALL_DIR}/caddy"
        shift 2
        ;;
      --config-path)
        CONFIG_PATH="${2:-}"
        CONFIG_DIR="$(dirname "$CONFIG_PATH")"
        shift 2
        ;;
      --service-name)
        SERVICE_NAME="${2:-}"
        SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
        shift 2
        ;;
      --go-version)
        GO_VERSION="${2:-}"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        fail "unknown argument: $1"
        ;;
    esac
  done

  if [[ "$UPGRADE_ONLY" -eq 1 ]]; then
    [[ -f "$CONFIG_PATH" ]] || fail "--upgrade requires existing config: ${CONFIG_PATH}"
  else
    [[ -n "$API_HOST" ]] || fail "--api-host is required"
    [[ -n "$NODE_ID" ]] || fail "--node-id is required"
    [[ -n "$API_KEY" ]] || fail "--api-key is required"
  fi
  case "$ENGINE" in
    caddy|legacy)
      ;;
    *)
      fail "--engine must be caddy or legacy"
      ;;
  esac
}

ensure_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    fail "please run as root"
  fi
}

install_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y curl git tar xz-utils ca-certificates
    return
  fi
  if command -v dnf >/dev/null 2>&1; then
    dnf install -y curl git tar xz ca-certificates
    return
  fi
  if command -v yum >/dev/null 2>&1; then
    yum install -y curl git tar xz ca-certificates
    return
  fi
  fail "unsupported package manager"
}

normalize_arch() {
  case "$(uname -m)" in
    x86_64|amd64)
      echo "amd64"
      ;;
    aarch64|arm64)
      echo "arm64"
      ;;
    *)
      fail "unsupported architecture: $(uname -m)"
      ;;
  esac
}

release_url() {
  local asset_name="$1"
  if [[ "$RELEASE_VERSION" == "latest" ]]; then
    echo "https://github.com/${REPO_SLUG}/releases/latest/download/${asset_name}"
    return
  fi
  echo "https://github.com/${REPO_SLUG}/releases/download/${RELEASE_VERSION}/${asset_name}"
}

download_patched_caddy_release() {
  local arch
  arch="$(normalize_arch)"
  local asset_name="v2naive_caddy_linux_${arch}.tar.gz"
  local url
  url="$(release_url "$asset_name")"
  local workdir
  workdir="$(mktemp -d /tmp/v2naive-caddy-release.XXXXXX)"
  local archive="${workdir}/${asset_name}"

  log "downloading patched naive caddy package ${asset_name}"
  if ! curl -fL --connect-timeout 15 --retry 3 "$url" -o "$archive"; then
    rm -rf "$workdir"
    return 1
  fi

  tar -xzf "$archive" -C "$workdir"
  [[ -f "${workdir}/caddy" ]] || fail "release archive missing caddy binary"
  mkdir -p "$INSTALL_DIR"
  install -m 0755 "${workdir}/caddy" "$CADDY_BIN_PATH"
  rm -rf "$workdir"
}

download_release_binary() {
  local arch
  arch="$(normalize_arch)"
  local asset_name="v2naive_linux_${arch}.tar.gz"
  local url
  url="$(release_url "$asset_name")"
  local workdir
  workdir="$(mktemp -d /tmp/v2naive-release.XXXXXX)"
  local archive="${workdir}/${asset_name}"

  log "downloading release package ${asset_name}"
  if ! curl -fL --connect-timeout 15 --retry 3 "$url" -o "$archive"; then
    rm -rf "$workdir"
    return 1
  fi

  tar -xzf "$archive" -C "$workdir"
  [[ -f "${workdir}/v2naive" ]] || fail "release archive missing v2naive binary"

  mkdir -p "$INSTALL_DIR"
  install -m 0755 "${workdir}/v2naive" "$BIN_PATH"
  rm -rf "$workdir"
}

ensure_go() {
  local current=""
  if command -v go >/dev/null 2>&1; then
    current="$(go version | awk '{print $3}' | sed 's/^go//')"
  fi

  if [[ -n "$current" ]] && version_ge "$current" "$MIN_GO_VERSION"; then
    log "using existing Go ${current}"
    GO_BIN="$(command -v go)"
    return
  fi

  local arch
  arch="$(normalize_arch)"
  local tarball="go${GO_VERSION}.linux-${arch}.tar.gz"
  local url="https://go.dev/dl/${tarball}"
  local tmpfile
  tmpfile="$(mktemp /tmp/v2naive-go.XXXXXX.tar.gz)"

  log "installing Go ${GO_VERSION}"
  curl -fsSL "$url" -o "$tmpfile"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$tmpfile"
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
  rm -f "$tmpfile"
  need_cmd go
  GO_BIN="$(command -v go)"
}

sync_repo() {
  mkdir -p "$INSTALL_DIR"
  if [[ -d "${SRC_DIR}/.git" ]]; then
    log "updating repository"
    git -C "$SRC_DIR" fetch --tags origin
    git -C "$SRC_DIR" checkout "$REPO_BRANCH"
    git -C "$SRC_DIR" reset --hard "origin/${REPO_BRANCH}"
  else
    rm -rf "$SRC_DIR"
    log "cloning repository"
    git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$SRC_DIR"
  fi
}

build_binary() {
  log "building v2naive"
  mkdir -p "$INSTALL_DIR"
  (
    cd "$SRC_DIR"
    "$GO_BIN" build -o "$BIN_PATH" .
  )
  chmod 0755 "$BIN_PATH"
}

build_naive_caddy() {
  ensure_go
  local gopath
  gopath="$("$GO_BIN" env GOPATH)"
  [[ -d "${SRC_DIR}/runtime/forwardproxy" ]] || fail "missing local forwardproxy runtime sources"
  log "building naive caddy runtime from source"
  "$GO_BIN" install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
  mkdir -p "$INSTALL_DIR"
  (
    cd "$INSTALL_DIR"
    "${gopath}/bin/xcaddy" build \
      --output "$CADDY_BIN_PATH" \
      --with github.com/caddyserver/forwardproxy="${SRC_DIR}/runtime/forwardproxy"
  )
  chmod 0755 "$CADDY_BIN_PATH"
}

install_caddy() {
  if [[ "$ENGINE" != "caddy" ]]; then
    return
  fi
  if [[ "$BUILD_FROM_SOURCE" -eq 0 ]] && download_patched_caddy_release; then
    log "installed patched naive caddy from GitHub release"
    return
  fi
  if [[ "$BUILD_FROM_SOURCE" -eq 0 ]]; then
    log "patched naive caddy release not available, falling back to source build"
  fi
  build_naive_caddy
}

install_binary() {
  if [[ "$BUILD_FROM_SOURCE" -eq 0 ]] && download_release_binary; then
    log "installed from GitHub release"
    return
  fi

  if [[ "$BUILD_FROM_SOURCE" -eq 0 ]]; then
    log "release package not available, falling back to source build"
  fi
  ensure_go
  sync_repo
  build_binary
}

write_config() {
  mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$STATE_DIR"
  touch "${LOG_DIR}/v2naive.log"

  if [[ -f "$CONFIG_PATH" ]]; then
    cp "$CONFIG_PATH" "${CONFIG_PATH}.bak.$(date +%s)"
  fi

  cat >"$CONFIG_PATH" <<EOF
Log:
  Level: info
  Output: ${LOG_DIR}/v2naive.log

Runtime:
  Engine: ${ENGINE}
  CaddyPath: ${CADDY_BIN_PATH}
  WorkingDir: ${STATE_DIR}
  AdminPortBase: 22019

Nodes:
  - ApiHost: "${API_HOST}"
    NodeID: ${NODE_ID}
    ApiKey: "${API_KEY}"
    Timeout: 15
    RetryCount: 2
EOF
}

write_service() {
  cat >"$SERVICE_PATH" <<EOF
[Unit]
Description=v2naive service
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BIN_PATH} -config ${CONFIG_PATH}
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}

write_logrotate() {
  cat >"$LOGROTATE_PATH" <<EOF
${LOG_DIR}/*.log {
  daily
  rotate 1
  size 50M
  missingok
  notifempty
  copytruncate
}
EOF
}

start_service() {
  need_cmd systemctl
  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"
  systemctl restart "$SERVICE_NAME"
  systemctl --no-pager --full status "$SERVICE_NAME" || true
}

main() {
  parse_args "$@"
  ensure_root
  install_packages
  install_binary
  sync_repo
  install_caddy
  if [[ "$UPGRADE_ONLY" -eq 0 ]]; then
    write_config
  fi
  write_service
  write_logrotate
  start_service
  if [[ "$UPGRADE_ONLY" -eq 1 ]]; then
    log "upgraded successfully"
  else
    log "installed successfully"
  fi
  log "config: ${CONFIG_PATH}"
  log "service: ${SERVICE_NAME}"
}

main "$@"
