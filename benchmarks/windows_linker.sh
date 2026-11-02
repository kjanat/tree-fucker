#!/usr/bin/env bash
# Cargo's GNU Windows linker entry point for the repository's Wine checks.
set -euo pipefail
arguments=()
for argument; do
	case "${argument}" in
		# Rust already names every static Rust archive explicitly. Zig treats
		# GNU's dynamic mode as DLL-only and skips MinGW import archives.
		-Wl,-Bstatic | -Wl,-Bdynamic | -Wl,--disable-auto-image-base) ;;
		-l:libpthread.a) arguments+=(-lpthread) ;;
		*) arguments+=("${argument}") ;;
	esac
done
exec zig cc -target x86_64-windows-gnu -L"${WINDOWS_SYSROOT:-target/native/windows/usr/x86_64-w64-mingw32}/lib" "${arguments[@]}"
