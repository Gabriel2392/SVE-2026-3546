#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

(( $# == 2 )) || { echo "usage: $0 BL PIT" >&2; exit 2; }

root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
bl="$(realpath -- "$1")"
pit="$(realpath -- "$2")"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/s5e8825-loader.XXXXXX")"
trap 'find "${tmp}" -depth -delete' EXIT
cd -- "${root}"

python3 resolve.py "${bl}"
python3 loader/bundle.py "${bl}" "${pit}" loader/bundle.bin loader/bundle_expected.h

aarch64-linux-gnu-as -o "${tmp}/start.o" loader/start.S
flags=(
    --target=aarch64-none-elf -Oz -ffreestanding -nostdlib -fno-builtin
    -fno-stack-protector -fomit-frame-pointer -fno-unwind-tables
    -fno-asynchronous-unwind-tables -mgeneral-regs-only -fno-pic -fno-pie
    -fno-unroll-loops -ffunction-sections -fdata-sections -I. -Iloader
)
clang "${flags[@]}" -c loader/payload.c -o "${tmp}/payload.o"
clang "${flags[@]}" -c loader/lzma_dec.c -o "${tmp}/lzma.o"
aarch64-linux-gnu-ld -T link.ld --build-id=none --gc-sections \
    -o "${tmp}/loader.elf" "${tmp}/start.o" "${tmp}/payload.o" "${tmp}/lzma.o"
aarch64-linux-gnu-objcopy -O binary -j .code "${tmp}/loader.elf" "${tmp}/loader.bin"

cc -O2 -Iloader loader/lzma_host.c loader/lzma_dec.c -o "${tmp}/lzma"
# python3 loader/check.py "${tmp}/loader.elf" "${tmp}/loader.bin" "${tmp}/lzma" "${tmp}"

install -m 0644 "${tmp}/loader.elf" loader.elf
install -m 0644 "${tmp}/loader.bin" loader.bin
sha256sum loader.bin loader/bundle.bin
