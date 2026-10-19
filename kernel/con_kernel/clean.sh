#!/bin/bash
# usage: bash clean.sh <KPATH>
# 只清理指定 KPATH 的中间产物和悬空软链，不碰 output*/ 里其它版本。
set -u

KPATH="${1:-}"
PWD_DIR="$(pwd)"

if [ -z "$KPATH" ] || [ ! -d "$KPATH" ]; then
    echo "[clean.sh] ERROR: invalid KPATH: '$KPATH'"
    echo "usage: bash clean.sh /root/code/code/linux/kernel/<ver>/build"
    exit 1
fi

echo "[clean.sh] clean KPATH=$KPATH"

# 1) kbuild 自己的 clean
make -I"$PWD_DIR" -C "$KPATH" M="$PWD_DIR" clean >/dev/null 2>&1 || true

# 2) 本模块在源码目录的残留（不碰 output*/ 里的历史版本）
rm -f "$PWD_DIR"/osec_base.ko
rm -f "$PWD_DIR"/osec_base.ko-*
rm -f "$PWD_DIR"/symbols*.txt
rm -f "$PWD_DIR"/static*.txt
rm -f "$PWD_DIR"/syms*.txt
rm -f "$PWD_DIR"/errors*.txt
rm -f "$PWD_DIR"/Module.symvers
rm -f "$PWD_DIR"/modules.order
rm -f "$PWD_DIR"/Module.markers
find "$PWD_DIR" -maxdepth 3 -name '*.o' -delete 2>/dev/null || true
find "$PWD_DIR" -maxdepth 3 -name '.*.cmd' -delete 2>/dev/null || true

# 3) 只删除“悬空”的 headers 软链，保留有效软链
for l in /usr/src/linux-headers-*-common; do
    [ -L "$l" ] && [ ! -e "$l" ] && rm -f "$l"
done

echo "[clean.sh] done"
