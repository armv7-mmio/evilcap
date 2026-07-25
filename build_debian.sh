#!/usr/bin/env bash

set -e

OUT_DIR="./package"

ARCH=$1

mkdir -p "$OUT_DIR"

dpkg-buildpackage -us -uc -b -a $1

LAST_CHANGES=$(ls -t ../*.changes 2>/dev/null | head -n 1)
if [ -n "$LAST_CHANGES" ]; then
	dcmd mv "$LAST_CHANGES" "$OUT_DIR/"
fi
