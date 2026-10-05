#!/usr/bin/env bash
# Shared default for standalone SDK owners and the complete adapter matrix.
set -euo pipefail
cpus="$(getconf _NPROCESSORS_ONLN)"
# Leave two CPUs available to interactive/server work on larger hosts.
jobs=$((cpus > 2 ? cpus - 2 : 1))
if (( jobs > 16 )); then jobs=16; fi
if [[ -r /proc/meminfo ]]; then
  available_kib="$(awk '$1 == "MemAvailable:" { print $2 }' /proc/meminfo)"
  # Respect a finite cgroup v2 memory budget as well as host availability.
  group="$(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup)"
  if [[ -r "/sys/fs/cgroup$group/memory.max" ]]; then
    limit="$(cat "/sys/fs/cgroup$group/memory.max")"
    used="$(cat "/sys/fs/cgroup$group/memory.current")"
    if [[ "$limit" != max ]]; then
      group_kib=$(((limit - used) / 1024))
      if (( group_kib < available_kib )); then available_kib=$group_kib; fi
    fi
  fi
  # Measurements include the full Rust/TypeScript pair and Bun client.
  # Reserve 4 GiB for the host and budget 1.5 GiB per active fixture pair.
  memory_jobs=$(((available_kib - 4 * 1024 * 1024) / (1536 * 1024)))
  if (( memory_jobs < 1 )); then memory_jobs=1; fi
  if (( memory_jobs < jobs )); then jobs=$memory_jobs; fi
else
  # Keep unmeasured hosts conservative; explicit overrides remain available.
  if (( jobs > 4 )); then jobs=4; fi
fi
printf '%s\n' "$jobs"
