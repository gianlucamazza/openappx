#!/usr/bin/env bash
# Optional: build Microsoft OSS makemsix (pack/sign) on Linux.
# Upstream: https://github.com/microsoft/msix-packaging
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_BIN="${ROOT}/tools/bin"
SRC="${OPENAPPX_MSIX_SRC:-${ROOT}/third_party/msix-packaging}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

mkdir -p "$OUT_BIN" "$(dirname "$SRC")"

if [[ ! -d "$SRC/.git" ]]; then
	echo "==> Cloning microsoft/msix-packaging ..."
	git clone --depth 1 https://github.com/microsoft/msix-packaging.git "$SRC"
fi

echo "==> Configuring (C++17, pack on) ..."
rm -rf "$SRC/.vs"
mkdir -p "$SRC/.vs"
cd "$SRC/.vs"
cmake -DCMAKE_BUILD_TYPE=Release \
	-DSKIP_BUNDLES=on \
	-DUSE_VALIDATION_PARSER=on \
	-DCMAKE_TOOLCHAIN_FILE=../cmake/linux.cmake \
	-DMSIX_PACK=on \
	-DMSIX_SAMPLES=off \
	-DMSIX_TESTS=off \
	-DLINUX=on \
	-DCMAKE_CXX_STANDARD=17 \
	-DCMAKE_CXX_STANDARD_REQUIRED=ON \
	..
make -j"$JOBS"

CANDIDATE=$(find "$SRC" -type f -name makemsix | head -1 || true)
if [[ -z "$CANDIDATE" ]]; then
	echo "error: makemsix not found — pure-Python pack still works" >&2
	exit 1
fi
install -m 755 "$CANDIDATE" "$OUT_BIN/makemsix"
SO_DIR=$(dirname "$CANDIDATE")
cp -a "$SO_DIR"/libmsix.so* "$OUT_BIN/" 2>/dev/null || true
echo "==> Installed $OUT_BIN/makemsix"
