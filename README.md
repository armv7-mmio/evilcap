# EvilCap

EvilCap is a kit of open source network security testing tools.

## Overview
- **Language:** C.
- **Build system:** GNU/Make.
- **Supported platform:** x86-64 Linux (Glibc/Musl).
- **Supported architectures:** x86-64, aarch64, mips.

## Project included tools:
- **EvilARP** - advanced ARP poisoning tool.
  - Supports one target and dual targets mode, gratuitous replies, ARP spam mode, adjustable random delay between packets.
  - For more see documentation in docs/EvilARP.md.

## Building from source
**Build requirements:**
- **clang**,
- **GNU/Make**,
- **glibc** or **musl libc**,
- **git**.

**For debian package build (optional):**
- **dpkg-dev**,
- **debhelper**,
- **devscripts**.

**Requirements install:**
- **For Debian**:
```shell
sudo apt install clang make debhelper devscripts dpkg-dev
```
- **For Arch Linux**:
```shell
sudo pacman -S base-devel clang
```
**Clone git repo:**
```shell
git clone https://github.com/armv7-mmio/evilcap
cd evilcap
```
**Start build:**
```shell
./build.sh [target] [architecture]
```
**Remove build files:**
```shell
./clean.sh
```
## License
MIT License. See LICENSE file for more.

