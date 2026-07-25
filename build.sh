#!/usr/bin/env bash

TARGET="${1:-debian}"
ARCH="${2:-amd64}"

case "$TARGET" in
	debian) ./build_debian.sh "$2" ;;
#	arch) ./build_arch.sh "$2" ;;
	*) echo "$TARGET is not supported to build"
esac

