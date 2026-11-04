#!/bin/sh
# awab installer — downloads the latest prebuilt binary for your platform.
#
#   curl -fsSL https://raw.githubusercontent.com/mechanicb0y/awab/main/install.sh | sh
#
# Env overrides:
#   AWAB_REPO   (default: mechanicb0y/awab)
#   AWAB_BINDIR (default: /usr/local/bin, falling back to ~/.local/bin)
#   AWAB_VERSION(default: latest)
set -eu

REPO="${AWAB_REPO:-mechanicb0y/awab}"
VERSION="${AWAB_VERSION:-latest}"

err() { printf 'awab-install: %s\n' "$1" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || err "missing required tool: $1"; }

need uname
need tar
if command -v curl >/dev/null 2>&1; then DL="curl -fsSL"; DLO="curl -fsSL -o";
elif command -v wget >/dev/null 2>&1; then DL="wget -qO-"; DLO="wget -qO";
else err "need curl or wget"; fi

os=$(uname -s)
arch=$(uname -m)

case "$os" in
  Linux) plat_os="unknown-linux-musl" ;;
  *) err "awab ships Linux binaries only ($os detected). Build from source instead:
    cargo install --git https://github.com/$REPO awab-cli";;
esac
case "$arch" in
  x86_64|amd64) plat_arch="x86_64" ;;
  aarch64|arm64) plat_arch="aarch64" ;;
  *) err "unsupported architecture: $arch";;
esac
target="${plat_arch}-${plat_os}"

if [ "$VERSION" = "latest" ]; then
  VERSION=$($DL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name"' | head -n1 | cut -d'"' -f4)
  [ -n "$VERSION" ] || err "could not determine the latest version"
fi

asset="awab-${VERSION}-${target}.tar.gz"
url="https://github.com/$REPO/releases/download/${VERSION}/${asset}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf 'Downloading %s ...\n' "$asset"
$DLO "$tmp/$asset" "$url" || err "download failed: $url"
tar xzf "$tmp/$asset" -C "$tmp"

# Pick an install dir we can actually write to.
bindir="${AWAB_BINDIR:-/usr/local/bin}"
if [ ! -w "$bindir" ] 2>/dev/null && [ "$(id -u)" -ne 0 ]; then
  bindir="$HOME/.local/bin"
  mkdir -p "$bindir"
fi

src=$(find "$tmp" -name awab -type f | head -n1)
[ -n "$src" ] || err "binary not found in archive"
install -m 0755 "$src" "$bindir/awab" 2>/dev/null || {
  cp "$src" "$bindir/awab" && chmod 0755 "$bindir/awab";
}

printf 'Installed awab %s to %s\n' "$VERSION" "$bindir/awab"
case ":$PATH:" in
  *":$bindir:"*) : ;;
  *) printf 'Note: add %s to your PATH.\n' "$bindir" ;;
esac
"$bindir/awab" --version || true
