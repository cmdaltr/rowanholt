# Volatility 3 symbol tables

Linux and macOS memory needs an ISF for the exact kernel the dump came from; Volatility 3
fetches Windows symbols itself but not these. Put `.json.xz` files in `linux/` or `mac/`
(mounted into the worker read-only) and recreate the worker. Make one with
[dwarf2json](https://github.com/volatilityfoundation/dwarf2json) from the kernel's debug
symbols, e.g. Ubuntu's `linux-image-unsigned-<version>-dbgsym`:

```bash
dwarf2json linux --elf vmlinux-5.8.0-44-generic --system-map System.map-5.8.0-44-generic | xz > linux/ubuntu-5.8.0-44-generic.json.xz
```

`build-ubuntu-isf.sh` does that in a throwaway container for an Ubuntu kernel (default: the test image's
`5.8.0-44-generic`, `5.8.0-44.50~20.04.1`, for which no prebuilt ISF is published).

The tables themselves aren't committed (`.gitignore`).
