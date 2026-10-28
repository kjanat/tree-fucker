#!/usr/bin/env bash
# Counts only; stdout/stderr pass through envctl before persistence.
set -euo pipefail
binary=$1
mode=$2
output=$3
mkdir -p "$(dirname "$output")"
command=("$binary" --scenario contention --mode "$mode" --workers 4 --iterations 20 --runs 1 --warmups 0)
case "$(uname -s)" in
  Linux)
    strace -f -c "${command[@]}" 2>&1 | envctl redact > "$output"
    ;;
  Darwin)
    printf -v quoted '%q ' "${command[@]}"
    sudo dtrace -q -n 'syscall:::entry /pid == $target || progenyof($target)/ { @calls[probefunc] = count(); }' \
      -c "$quoted" 2>&1 | envctl redact > "$output"
    ;;
  *) echo "Unsupported trace host" >&2; exit 1 ;;
esac
# DTrace's own success is not proof that the workload finished. Require its
# complete verified benchmark row and at least one syscall count as well.
awk -F '\t' -v mode="$mode" '$1 == "contention" && $2 == mode && NF == 21 { found++ } END { exit found != 1 }' "$output"
if [[ "$(uname -s)" == Linux ]]; then
  grep -Eq ' +[0-9]+ +total$' "$output"
else
  grep -Eq '^[[:space:]]+[[:alnum:]_]+[[:space:]]+[1-9][0-9]*[[:space:]]*$' "$output"
fi
