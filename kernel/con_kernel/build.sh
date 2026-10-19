#!/bin/bash
set -u
cd "$(dirname "$0")"

# 本环境 GCC（按镜像实际装了的写）
export CC=${CC:-gcc-9}

OUT_DIR=${OUT_DIR:-output_ecn}
KROOT=/root/code/code/linux/kernel

run() {
  local kver="$1" kpath="$2"
  bash build_one.sh "$kver" "$kpath" "$OUT_DIR" \
    && echo "OK   $kver" || echo "FAIL $kver"
}

# ---- 2.6.32 EL6 ----
run 2.6.32-431.el6.x86_64          "$KROOT/2.6.32-431.el6.x86_64/build"
run 2.6.32-504.el6.x86_64          "$KROOT/0629_centos/2.6.32-504.el6.x86_64/build"
run 2.6.32-642.el6.x86_64          "$KROOT/0629_centos/2.6.32-642.el6.x86_64/build"
run 2.6.32-696.el6.x86_64          "$KROOT/0629_centos/2.6.32-696.el6.x86_64/build"

# ---- 3.10 EL7 ----
run 3.10.0-123.el7.x86_64          "$KROOT/3.10.0-123.el7.x86_64/build"
run 3.10.0-229.el7.x86_64          "$KROOT/3.10.0-229.el7.x86_64/build"
run 3.10.0-327.el7.x86_64          "$KROOT/centos/3.10.0-327.el7.x86_64/build"
run 3.10.0-514.el7.x86_64          "$KROOT/0629_centos/3.10.0-514.el7.x86_64/build"
run 3.10.0-693.el7.x86_64          "$KROOT/0629_centos/3.10.0-693.el7.x86_64/build"
run 3.10.0-693.2.2.el7.x86_64      "$KROOT/3.10.0-693.2.2.el7.x86_64/build"
run 3.10.0-862.el7.x86_64          "$KROOT/0629_centos/3.10.0-862.el7.x86_64/build"
run 3.10.0-862.14.4.el7.x86_64     "$KROOT/3.10.0-862.14.4.el7.x86_64/build"
run 3.10.0-957.el7.x86_64          "$KROOT/3.10.0-957.el7.x86_64/build"
run 3.10.0-957.12.2.el7.x86_64     "$KROOT/3.10.0-957.12.2.el7.x86_64/build"
run 3.10.0-957.21.3.el7.x86_64     "$KROOT/3.10.0-957.21.3.el7.x86_64/build"
run 3.10.0-1062.el7.x86_64         "$KROOT/3.10.0-1062.el7.x86_64/build"
run 3.10.0-1062.9.1.el7.x86_64     "$KROOT/3.10.0-1062.9.1.el7.x86_64/build"
run 3.10.0-1062.12.1.el7.x86_64    "$KROOT/centos/3.10.0-1062.12.1.el7.x86_64/build"
run 3.10.0-1062.18.1.el7.x86_64    "$KROOT/3.10.0-1062.18.1.el7.x86_64/build"
run 3.10.0-1127.10.1.el7.x86_64    "$KROOT/centos/3.10.0-1127.10.1.el7.x86_64/build"
run 3.10.0-1127.19.1.el7.x86_64    "$KROOT/3.10.0-1127.19.1.el7.x86_64/build"
run 3.10.0-1160.el7.x86_64         "$KROOT/3.10.0-1160.el7.x86_64/build"
run 3.10.0-1160.6.1.el7.x86_64     "$KROOT/3.10.0-1160.6.1.el7.x86_64/build"
run 3.10.0-1160.25.1.el7.x86_64    "$KROOT/3.10.0-1160.25.1.el7.x86_64/build"
run 3.10.0-1160.76.1.el7.x86_64    "$KROOT/3.10.0-1160.76.1.el7.x86_64/build"
run 3.10.0-1160.92.1.el7.x86_64    "$KROOT/3.10.0-1160.92.1.el7.x86_64/build"
run 3.10.0-1160.95.1.el7.x86_64    "$KROOT/3.10.0-1160.95.1.el7.x86_64/build"
run 3.10.0-1160.114.2.el7.x86_64   "$KROOT/3.10.0-1160.114.2.el7.x86_64/build"
run 3.10.0-1160.119.1.el7.x86_64   "$KROOT/3.10.0-1160.119.1.el7.x86_64/build"

# ---- 3.12 / 4.x 老 ----
run 3.12.11-201.nk.1.x86_64        "$KROOT/3.12.11-201.nk.1.x86_64/build"
run 4.4.0-21-generic               "$KROOT/0629_ubuntu/4.4.0-21-generic/build"
run 4.4.0-142-generic              "$KROOT/4.4.0-142-generic/build"
run 4.4.0-148-generic              "$KROOT/0629_ubuntu/4.4.0-148-generic/build"
run 4.4.13-200.nd7.1.x86_64        "$KROOT/4.4.13-200.nd7.1.x86_64/build"
run 4.8.0-36-generic               "$KROOT/4.8.0-36-generic/build"
run 4.12.14-120-default            "$KROOT/4.12.14-120-default/4.12.14-120/4.12.14-120-default/build"
run 4.15.0-20-generic              "$KROOT/4.15.0-20-generic/build"
run 4.15.0-30deepin-generic        "$KROOT/4.15.0-30deepin-generic/build"
run 4.15.0-55-generic              "$KROOT/4.15.0-55-generic/build"
run 4.15.0-72-generic              "$KROOT/4.15.0-72-generic/build"
run 4.15.0-88-generic              "$KROOT/4.15.0-88-generic/build"
run 4.15.0-118-generic             "$KROOT/4.15.0-118-generic/build"
run 4.15.0-167-generic             "$KROOT/4.15.0-167-generic/build"
run 4.15.0-212-generic             "$KROOT/4.15.0-212-generic/build"
run 4.15.0-213-generic             "$KROOT/4.15.0-213-generic/build"
run 4.17.11-1.el7.elrepo.x86_64    "$KROOT/4.17.11-1.el7.elrepo.x86_64/build"
