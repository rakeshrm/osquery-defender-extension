#!/usr/bin/env bash
# Cross-compile the Defender MpEngineDb osquery extension.
# Run from the repo root. Output: bin/defender-mpengine-<os>-<arch>.ext[.exe] + bin/SHA256SUMS
# Local builds: VERSION=0.1.0 ./build.sh, else the nearest tag / commit, else "dev".
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$ROOT/defender"
OUTPUT_DIR="$ROOT/bin"

VERSION="${VERSION:-$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || true)}"
VERSION="${VERSION:-dev}"

platforms=(
	"windows/amd64" "windows/arm64"
	"linux/amd64" "linux/arm64"
	"darwin/amd64" "darwin/arm64"
)

mkdir -p "$OUTPUT_DIR"
cd "$SRC_DIR"

outputs=()
for platform in "${platforms[@]}"; do
	GOOS="${platform%/*}"
	GOARCH="${platform#*/}"
	name="defender-mpengine-$GOOS-$GOARCH.ext"
	[ "$GOOS" = "windows" ] && name+=".exe"

	CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
		go build -trimpath -ldflags "-s -w -X main.Version=$VERSION" -o "$OUTPUT_DIR/$name" .
	echo "built bin/$name"
	outputs+=("$name")
done

cd "$OUTPUT_DIR"
if command -v sha256sum >/dev/null 2>&1; then
	sha256sum "${outputs[@]}" > SHA256SUMS
else
	shasum -a 256 "${outputs[@]}" > SHA256SUMS
fi
echo "wrote bin/SHA256SUMS (version $VERSION)"
