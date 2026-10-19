#!/bin/bash
set -u
cd "$(dirname "$0")"

# 不设置全局 CC，交给 build_one.sh 按 KVER 自动选
# 如需强制本环境统一用某个 GCC：CC=gcc-11 bash build_high_kernel_v1.sh

OUT_DIR=${OUT_DIR:-output_ecn}
KROOT=/root/code/code/linux/kernel

run() {
  local kver="$1" kpath="$2"
  bash build_one.sh "$kver" "$kpath" "$OUT_DIR" \
    && echo "OK   $kver" || echo "FAIL $kver"
}

# ---- 4.18 EL8 ----
run 4.18.0-15-generic              "$KROOT/4.18.0-15-generic/build"
run 4.18.0-16-generic              "$KROOT/4.18.0-16-generic/build"
run 4.18.0-193.el8.x86_64          "$KROOT/4.18.0-193.el8.x86_64/build"
run 4.18.0-305.3.1.el8.x86_64      "$KROOT/4.18.0-305.3.1.el8.x86_64/build"
run 4.18.0-348.el8.x86_64          "$KROOT/4.18.0-348.el8.x86_64/build"
run 4.18.0-348.20.1.el8_5.x86_64   "$KROOT/4.18.0-348.20.1.el8_5.x86_64/build"
run 4.18.0-372.9.1.el8.x86_64      "$KROOT/4.18.0-372.9.1.el8.x86_64/build"
run 4.18.0-372.9.1.an8.x86_64      "$KROOT/4.18.0-372.9.1.an8.x86_64/build"
run 4.18.0-372.32.1.el8_6.x86_64   "$KROOT/4.18.0-372.32.1.el8_6.x86_64/build"
run 4.18.0-425.19.2.el8_7.x86_64   "$KROOT/4.18.0-425.19.2.el8_7.x86_64/build"
run 4.18.0-477.21.1.el8_8.x86_64   "$KROOT/4.18.0-477.21.1.el8_8.x86_64/build"
run 4.18.0-477.27.1.el8_8.x86_64   "$KROOT/4.18.0-477.27.1.el8_8.x86_64/build"
run 4.18.0-513.18.1.el8_9.x86_64   "$KROOT/4.18.0-513.18.1.el8_9.x86_64/build"
run 4.18.0-540.el8.x86_64          "$KROOT/4.18.0-540.el8.x86_64/build"

# ---- 4.19 ----
run 4.19.0-6-amd64                 "$KROOT/4.19.0-6-amd64/build"
run 4.19.0-91.82.179.uelc20.x86_64 "$KROOT/4.19.0-91.82.179.uelc20.x86_64/build"
run 4.19.90-89.11.v2401.ky10.x86_64 "$KROOT/4.19.90-89.11.v2401.ky10.x86_64/build"
run 4.19.90-89.40.v2401.ky10.x86_64 "$KROOT/4.19.90-89.40.v2401.ky10.x86_64/build"
run 4.19.91-23.4.an8.x86_64        "$KROOT/4.19.91-23.4.an8.x86_64/build"
run 4.19.91-24.8.an7.x86_64        "$KROOT/4.19.91-24.8.an7.x86_64/build"
run 4.19.91-25.7.an8.x86_64        "$KROOT/4.19.91-25.7.an8.x86_64/build"
run 4.19.91-26.5.an8.x86_64        "$KROOT/4.19.91-26.5.an8.x86_64/build"
run 4.19.91-26.6.an8.x86_64        "$KROOT/4.19.91-26.6.an8.x86_64/build"
run 4.19.91-26.an7.x86_64          "$KROOT/4.19.91-26.an7.x86_64/build"
run 4.19.91-26.an8.x86_64          "$KROOT/4.19.91-26.an8.x86_64/build"
run 4.19.91-27.1.an7.x86_64        "$KROOT/4.19.91-27.1.an7.x86_64/build"
run 4.19.91-28.2.al7.x86_64        "$KROOT/4.19.91-28.2.al7.x86_64/build"
run 4.19.91-28.7.an8.x86_64        "$KROOT/4.19.91-28.7.an8.x86_64/build"

# ---- 5.4 ----
run 5.4.0-26-generic               "$KROOT/5.4.0-26-generic/build"
run 5.4.0-42-generic               "$KROOT/5.4.0-42-generic/build"
run 5.4.0-81-generic               "$KROOT/5.4.0-81-generic/build"
run 5.4.0-84-generic               "$KROOT/5.4.0-84-generic/build"
run 5.4.0-106-generic              "$KROOT/5.4.0-106-generic/build"
run 5.4.0-131-generic              "$KROOT/5.4.0-131-generic/build"
run 5.4.0-169-generic              "$KROOT/5.4.0-169-generic/build"
run 5.4.0-182-generic              "$KROOT/5.4.0-182-generic/build"
run 5.4.0-190-generic              "$KROOT/5.4.0-190-generic/build"
run 5.4.0-192-generic              "$KROOT/5.4.0-192-generic/build"
run 5.4.0-216-generic              "$KROOT/5.4.0-216-generic/build"
run 5.4.18-110-generic             "$KROOT/5.4.18-110-generic/build"
run 5.4.18-132-generic             "$KROOT/5.4.18-132-generic/build"
run 5.4.119-20.0009.20             "$KROOT/5.4.119-20.0009.20/build"
run 5.4.119-20.0009.31             "$KROOT/5.4.119-20.0009.31/build"
run 5.4.219-1.el7.elrepo.x86_64    "$KROOT/5.4.219-1.el7.elrepo.x86_64/build"
run 5.4.272-1.el7.elrepo.x86_64    "$KROOT/5.4.272-1.el7.elrepo.x86_64/build"
run 5.4.278-1.el7.elrepo.x86_64    "$KROOT/5.4.278-1.el7.elrepo.x86_64/build"

# ---- 5.10 ----
run 5.10.0-9-generic               "$KROOT/5.10.0-9-generic/build"
run 5.10.0-15-generic              "$KROOT/5.10.0-15-generic/build"
run 5.10.0-136.35.0.111.u63.fos23.x86_64 "$KROOT/5.10.0-136.35.0.111.u63.fos23.x86_64/build"
run 5.10.134-13.1.an8.x86_64       "$KROOT/5.10.134-13.1.an8.x86_64/build"
run 5.10.134-15.al8.x86_64         "$KROOT/5.10.134-15.al8.x86_64/build"
run 5.10.134-16.1.al8.x86_64       "$KROOT/5.10.134-16.1.al8.x86_64/build"
run 5.10.134-16.3.al8.x86_64       "$KROOT/5.10.134-16.3.al8.x86_64/build"
run 5.10.134-17.1.al8.x86_64       "$KROOT/5.10.134-17.1.al8.x86_64/build"
run 5.10.134-18.an8.x86_64         "$KROOT/5.10.134-18.an8.x86_64/build"

# ---- 5.14 ----
run 5.14.0-70.26.1.el9_0.x86_64    "$KROOT/5.14.0-70.26.1.el9_0.x86_64/build"
run 5.14.0-70.30.1.el9_0.x86_64    "$KROOT/5.14.0-70.30.1.el9_0.x86_64/build"
run 5.14.0-162.23.1.el9_1.x86_64   "$KROOT/5.14.0-162.23.1.el9_1.x86_64/build"
run 5.14.0-284.11.1.el9_2.x86_64   "$KROOT/5.14.0-284.11.1.el9_2.x86_64/build"
run 5.14.0-284.30.1.el9_2.x86_64   "$KROOT/5.14.0-284.30.1.el9_2.x86_64/build"
run 5.14.0-362.24.1.el9_3.0.1.x86_64 "$KROOT/5.14.0-362.24.1.el9_3.0.1.x86_64/build"
run 5.14.0-362.24.2.el9_3.x86_64   "$KROOT/5.14.0-362.24.2.el9_3.x86_64/build"
run 5.14.0-427.18.1.el9_4.x86_64   "$KROOT/5.14.0-427.18.1.el9_4.x86_64/build"
run 5.14.0-427.22.1.el9_4.x86_64   "$KROOT/5.14.0-427.22.1.el9_4.x86_64/build"
run 5.14.0-444.el9.x86_64          "$KROOT/5.14.0-444.el9.x86_64/build"
