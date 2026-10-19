#!/bin/bash
set -u
cd "$(dirname "$0")"

KROOT=/root/code/code/linux/kernel

run() {
  local kver="$1" kpath="$2"
  bash build_one.sh "$kver" "$kpath" \
    && echo "OK   $kver" || echo "FAIL $kver"
}

# ---- 5.11 / 5.13 / 5.15 / 5.16 / 5.18 / 5.19 ----
run 5.11.7-200.fc33.x86_64         "$KROOT/5.11.7-200.fc33.x86_64/build"
run 5.13.5-1.el7.elrepo.x86_64     "$KROOT/5.13.5-1.el7.elrepo.x86_64/build"
run 5.15.0-43-generic              "$KROOT/5.15.0-43-generic/build"
run 5.15.0-60-generic              "$KROOT/5.15.0-60-generic/build"
run 5.15.0-67-generic              "$KROOT/5.15.0-67-generic/build"
run 5.15.0-69-generic              "$KROOT/5.15.0-69-generic/build"
run 5.15.0-87-generic              "$KROOT/5.15.0-87-generic/build"
run 5.15.0-91-generic              "$KROOT/5.15.0-91-generic/build"
run 5.15.0-102-generic             "$KROOT/5.15.0-102-generic/build"
run 5.15.0-107-generic             "$KROOT/5.15.0-107-generic/build"
run 5.15.0-113-generic             "$KROOT/5.15.0-113-generic/build"
run 5.15.0-119-generic             "$KROOT/5.15.0-119-generic/build"
run 5.15.0-131-generic             "$KROOT/5.15.0-131-generic/build"
run 5.15.0-136-generic             "$KROOT/5.15.0-136-generic/build"
run 5.15.0-139-generic             "$KROOT/5.15.0-139-generic/build"
run 5.15.0-143-generic             "$KROOT/5.15.0-143-generic/build"
run 5.15.0-157-generic             "$KROOT/5.15.0-157-generic/build"
run 5.15.0-161-generic             "$KROOT/5.15.0-161-generic/build"
run 5.15.0-164-generic             "$KROOT/5.15.0-164-generic/build"
run 5.15.0-171-generic             "$KROOT/5.15.0-171-generic/build"
run 5.15.0-174-generic             "$KROOT/5.15.0-174-generic/build"
run 5.15.0-181-generic             "$KROOT/5.15.0-181-generic/build"
run 5.16.15-101.fc34.x86_64        "$KROOT/5.16.15-101.fc34.x86_64/build"
run 5.18.18-100.fc35.x86_64        "$KROOT/5.18.18-100.fc35.x86_64/build"
run 5.19.0-21-generic              "$KROOT/5.19.0-21-generic/build"
run 5.19.0-32-generic              "$KROOT/5.19.0-32-generic/build"
run 5.19.0-43-generic              "$KROOT/5.19.0-43-generic/build"
run 5.19.0-46-generic              "$KROOT/5.19.0-46-generic/build"

# ---- 6.0 / 6.1 / 6.2 ----
run 6.0.7-301.fc37.x86_64          "$KROOT/6.0.7-301.fc37.x86_64/build"
run 6.1.0-21-amd64                 "$KROOT/6.1.0-21-amd64/build"
run 6.1.0-22-amd64                 "$KROOT/6.1.0-22-amd64/build"
run 6.2.0-20-generic               "$KROOT/6.2.0-20-generic/build"
run 6.2.0-26-generic               "$KROOT/6.2.0-26-generic/build"
run 6.2.0-39-generic               "$KROOT/6.2.0-39-generic/build"
run 6.2.9-300.fc38.x86_64          "$KROOT/6.2.9-300.fc38.x86_64/build"

# ---- 6.5 ----
run 6.5.0-28-generic               "$KROOT/6.5.0-28-generic/build"
run 6.5.0-35-generic               "$KROOT/6.5.0-35-generic/build"
run 6.5.0-41-generic               "$KROOT/6.5.0-41-generic/build"
run 6.5.6-300.fc39.x86_64          "$KROOT/6.5.6-300.fc39.x86_64/build"

# ---- 6.6 国产 ----
run 6.6.0-32.7.v2505.ky11.x86_64   "$KROOT/6.6.0-32.7.v2505.ky11.x86_64/build"
run 6.6.0-145.0.2.143.oe2403sp2.x86_64 "$KROOT/6.6.0-145.0.2.143.oe2403sp2.x86_64/build"

# ---- 6.8 Ubuntu ----
run 6.8.0-45-generic               "$KROOT/6.8.0-45-generic/build"
run 6.8.0-47-generic               "$KROOT/6.8.0-47-generic/build"
run 6.8.0-49-generic               "$KROOT/6.8.0-49-generic/build"
run 6.8.0-50-generic               "$KROOT/6.8.0-50-generic/build"
run 6.8.0-51-generic               "$KROOT/6.8.0-51-generic/build"
run 6.8.0-57-generic               "$KROOT/6.8.0-57-generic/build"
run 6.8.0-58-generic               "$KROOT/6.8.0-58-generic/build"
run 6.8.0-65-generic               "$KROOT/6.8.0-65-generic/build"
run 6.8.0-71-generic               "$KROOT/6.8.0-71-generic/build"
run 6.8.0-79-generic               "$KROOT/6.8.0-79-generic/build"
run 6.8.0-83-generic               "$KROOT/6.8.0-83-generic/build"
run 6.8.0-84-generic               "$KROOT/6.8.0-84-generic/build"
run 6.8.0-85-generic               "$KROOT/6.8.0-85-generic/build"
run 6.8.0-87-generic               "$KROOT/6.8.0-87-generic/build"
run 6.8.0-88-generic               "$KROOT/6.8.0-88-generic/build"
run 6.8.0-90-generic               "$KROOT/6.8.0-90-generic/build"
run 6.8.0-101-generic              "$KROOT/6.8.0-101-generic/build"
run 6.8.0-107-generic              "$KROOT/6.8.0-107-generic/build"
run 6.8.0-110-generic              "$KROOT/6.8.0-110-generic/build"
run 6.8.0-111-generic              "$KROOT/6.8.0-111-generic/build"
