#!/usr/bin/env bash
# Cross-build libsodchan + libsodium for OpenWrt ipq807x_32 (armv7-eabihf musl).
#
# Output:
#   build-ipq807x_32/libsodchan.a
#   third_party/sodium-armv7-prefix/lib/libsodium.a  (built once if missing)
#
# Usage:
#   ./scripts/cross_build_ipq807x_32.sh
#   BOOTLIN_TOOLCHAIN=/path/to/tc ./scripts/cross_build_ipq807x_32.sh
#
# netforensics cross_build_ipq807x.sh --32 will pick up build-ipq807x_32/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${BUILD_DIR:-${ROOT}/build-ipq807x_32}"
SODIUM_PREFIX="${SODIUM_PREFIX:-${ROOT}/third_party/sodium-armv7-prefix}"
SODIUM_VER="${SODIUM_VER:-1.0.20}"
NF_TC="${ROOT}/../netforensics/cmake/toolchains/armv7-eabihf-bootlin.cmake"

pick_bootlin() {
  local c
  if [[ -n "${BOOTLIN_TOOLCHAIN:-}" && -d "${BOOTLIN_TOOLCHAIN}" ]]; then
    echo "${BOOTLIN_TOOLCHAIN}"
    return 0
  fi
  for c in "${HOME}"/toolchains/armv7-eabihf--musl--*; do
    if [[ -d "$c" && -d "$c/bin" ]]; then
      echo "$c"
      return 0
    fi
  done
  return 1
}

tc=$(pick_bootlin) || {
  echo "error: Bootlin armv7-eabihf musl toolchain not found under ~/toolchains/" >&2
  exit 1
}
cc=$(echo "${tc}"/bin/*-linux-*-gcc | awk '{print $1}')
[[ -x "$cc" ]] || { echo "error: no gcc in ${tc}/bin" >&2; exit 1; }
sysroot=$(echo "${tc}"/arm-buildroot-linux-musleabihf/sysroot)
host=arm-buildroot-linux-musleabihf

echo "=== libsodchan armv7 (ipq807x_32) ==="
echo "  toolchain: ${tc}"
echo "  build:     ${BUILD}"
echo "  sodium:    ${SODIUM_PREFIX}"

# --- libsodium (target static) ---
if [[ ! -f "${SODIUM_PREFIX}/lib/libsodium.a" ]]; then
  echo "==> building libsodium ${SODIUM_VER} for armv7"
  src="${SODIUM_SRC:-/tmp/libsodium-${SODIUM_VER}}"
  if [[ ! -d "$src" ]]; then
    tgz="/tmp/libsodium-${SODIUM_VER}.tar.gz"
    if [[ ! -f "$tgz" ]]; then
      curl -fsSL -o "$tgz" \
        "https://download.libsodium.org/libsodium/releases/libsodium-${SODIUM_VER}.tar.gz" \
        || curl -fsSL -o "$tgz" \
        "https://github.com/jedisct1/libsodium/releases/download/${SODIUM_VER}-RELEASE/libsodium-${SODIUM_VER}.tar.gz"
    fi
    tar -xzf "$tgz" -C /tmp
    # tarball extracts as libsodium-VER
    src="/tmp/libsodium-${SODIUM_VER}"
  fi
  (
    cd "$src"
    make distclean 2>/dev/null || true
    ./configure \
      --host="${host}" \
      --prefix="${SODIUM_PREFIX}" \
      --enable-static \
      --disable-shared \
      --disable-dependency-tracking \
      CC="${cc}" \
      CFLAGS="-Os -march=armv7-a -mfpu=neon-vfpv4 -mfloat-abi=hard --sysroot=${sysroot}" \
      LDFLAGS="--sysroot=${sysroot}"
    make -j"$(nproc 2>/dev/null || echo 2)"
    make install
  )
fi
file "${SODIUM_PREFIX}/lib/libsodium.a"

# --- libsodchan ---
rm -rf "${BUILD}/CMakeCache.txt" "${BUILD}/CMakeFiles" 2>/dev/null || true
CMAKE_ARGS=(
  -B "${BUILD}"
  -S "${ROOT}"
  -DCMAKE_BUILD_TYPE=MinSizeRel
  -DBUILD_TESTING=OFF
  -DENABLE_FUZZ=OFF
  -DSODIUM_ROOT="${SODIUM_PREFIX}"
  -DSodium_INCLUDE_DIR="${SODIUM_PREFIX}/include"
  -DSodium_LIBRARY="${SODIUM_PREFIX}/lib/libsodium.a"
  -DBOOTLIN_TOOLCHAIN="${tc}"
)
if [[ -f "${NF_TC}" ]]; then
  CMAKE_ARGS+=(-DCMAKE_TOOLCHAIN_FILE="${NF_TC}")
else
  CMAKE_ARGS+=(
    -DCMAKE_SYSTEM_NAME=Linux
    -DCMAKE_SYSTEM_PROCESSOR=arm
    -DCMAKE_C_COMPILER="${cc}"
    -DCMAKE_C_FLAGS="-march=armv7-a -mfpu=neon-vfpv4 -mfloat-abi=hard"
    -DCMAKE_FIND_ROOT_PATH="${sysroot}"
    -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY
    -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY
    -DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY
    -DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER
  )
fi

cmake "${CMAKE_ARGS[@]}"
cmake --build "${BUILD}" -j"$(nproc 2>/dev/null || echo 2)" --target sodchan

[[ -f "${BUILD}/libsodchan.a" ]] || {
  echo "error: missing ${BUILD}/libsodchan.a" >&2
  exit 1
}

echo
file "${BUILD}/libsodchan.a"
tmpdir=$(mktemp -d)
(cd "${tmpdir}" && ar x "${BUILD}/libsodchan.a" && file ./*.o | head -5)
rm -rf "${tmpdir}"

echo
echo "OK: ${BUILD}/libsodchan.a"
echo "    sodium: ${SODIUM_PREFIX}/lib/libsodium.a"
echo "  netforensics: reconfigure build-ipq807x_32 (or run scripts/cross_build_ipq807x.sh --32)"
echo "  Pass -DSODIUM_ROOT=${SODIUM_PREFIX} if sodium is not auto-detected."
