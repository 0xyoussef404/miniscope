#!/usr/bin/env bash
set -euo pipefail

# Colors
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

say() { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[-]${NC} $*"; exit 1; }

need() { command -v "$1" >/dev/null 2>&1; }

# 1) Base deps
say "Installing base dependencies (git, curl, unzip, golang)"
sudo apt update -y
sudo apt install -y git curl wget unzip ca-certificates build-essential
if ! need go; then
  sudo apt install -y golang
fi

# Ensure GOPATH/bin is on PATH
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin"

# 2) Go tools
install_go_tool() {
  local pkg="$1"; local name="$2"
  if need "$2"; then say "$2 already installed"; return; fi
  say "Installing $2"
  go install -v "$pkg" || fail "go install failed for $2"
}

install_go_tool github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest subfinder
install_go_tool github.com/tomnomnom/assetfinder@latest assetfinder
install_go_tool github.com/projectdiscovery/dnsx/cmd/dnsx@latest dnsx
install_go_tool github.com/projectdiscovery/katana/cmd/katana@latest katana

# 3) Amass
if need amass; then
  say "amass already installed"
else
  if apt-cache show owasp-amass >/dev/null 2>&1; then
    sudo apt install -y owasp-amass || true
  fi
  if ! need amass; then
    install_go_tool github.com/owasp-amass/amass/v4/...@master amass
  fi
fi

# 4) Findomain
if ! need findomain; then
  say "Installing findomain"
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64|amd64) URL="https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip" ;;
    aarch64|arm64) URL="https://github.com/findomain/findomain/releases/latest/download/findomain-aarch64.zip" ;;
    armv7l|armv7) URL="https://github.com/findomain/findomain/releases/latest/download/findomain-armv7.zip" ;;
    *) URL="https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip" ;;
  esac
  TMP=$(mktemp -d)
  ( cd "$TMP" && wget -q "$URL" -O fd.zip && unzip -o fd.zip && sudo mv -f findomain /usr/local/bin/ && sudo chmod +x /usr/local/bin/findomain )
  rm -rf "$TMP"
fi

# 5) Python deps
if need python3; then
  say "Installing Python requirements"
  python3 -m pip install -U pip
  if [ -f requirements.txt ]; then
    python3 -m pip install -r requirements.txt
  else
    python3 -m pip install httpx colorama
  fi
else
  warn "python3 not found; skipping Python deps"
fi

say "All tools ready!"
