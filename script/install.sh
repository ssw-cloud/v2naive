#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/ssw-cloud/v2naive.git}"
REPO_BRANCH="${REPO_BRANCH:-main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/v2naive}"
SRC_DIR="${SRC_DIR:-${INSTALL_DIR}/src}"
BIN_PATH="${BIN_PATH:-${INSTALL_DIR}/v2naive}"
CONFIG_DIR="${CONFIG_DIR:-/etc/v2naive}"
CONFIG_PATH="${CONFIG_PATH:-${CONFIG_DIR}/config.yml}"
SERVICE_NAME="${SERVICE_NAME:-v2naive}"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
LOG_DIR="${LOG_DIR:-/var/log/v2naive}"
GO_VERSION="${GO_VERSION:-1.25.6}"
MIN_GO_VERSION="${MIN_GO_VERSION:-1.24.0}"
GO_BIN=""

API_HOST=""
NODE_ID=""
API_KEY=""

usage() {
  cat <<'EOF'
Usage:
  bash install.sh --api-host https://panel.example.com --node-id 1 --api-key your-token

Optional flags:
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
      --repo-branch)
        REPO_BRANCH="${2:-}"
        shift 2
        ;;
      --install-dir)
        INSTALL_DIR="${2:-}"
        SRC_DIR="${INSTALL_DIR}/src"
        BIN_PATH="${INSTALL_DIR}/v2naive"
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

  [[ -n "$API_HOST" ]] || fail "--api-host is required"
  [[ -n "$NODE_ID" ]] || fail "--node-id is required"
  [[ -n "$API_KEY" ]] || fail "--api-key is required"
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
    apt-get install -y curl git tar ca-certificates
    return
  fi
  if command -v dnf >/dev/null 2>&1; then
    dnf install -y curl git tar ca-certificates
    return
  fi
  if command -v yum >/dev/null 2>&1; then
    yum install -y curl git tar ca-certificates
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

write_config() {
  mkdir -p "$CONFIG_DIR" "$LOG_DIR"
  touch "${LOG_DIR}/v2naive.log"

  if [[ -f "$CONFIG_PATH" ]]; then
    cp "$CONFIG_PATH" "${CONFIG_PATH}.bak.$(date +%s)"
  fi

  cat >"$CONFIG_PATH" <<EOF
Log:
  Level: info
  Output: ${LOG_DIR}/v2naive.log

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
  ensure_go
  sync_repo
  build_binary
  write_config
  write_service
  start_service
  log "installed successfully"
  log "config: ${CONFIG_PATH}"
  log "service: ${SERVICE_NAME}"
}

main "$@"
