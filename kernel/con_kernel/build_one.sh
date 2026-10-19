#!/bin/bash
# usage: bash build_one.sh <KVER> <KPATH>
# 成功: 产物在 <Makefile 决定的 OUT_DIR>/osec_base.ko-<KVER>，删除单版本日志，返回 0
# 失败: 保留 build_one.<KVER>.log，返回 1
# 说明:
#   - OUT_DIR / TCP_ECN_FEATURE 完全以 Makefile 为准，脚本不猜、不传；
#   - 若调用方 export CC=xxx，则尊重调用方；否则按 KVER 选环境里存在的 GCC；
#   - 候选列表每个分支最后都有 gcc 兜底。
set -u

KVER="$1"
KPATH="$2"
PWD_DIR="$(pwd)"

if [ -z "${KVER:-}" ] || [ -z "${KPATH:-}" ]; then
    echo "usage: bash build_one.sh <KVER> <KPATH>"
    exit 2
fi
if [ ! -d "$KPATH" ]; then
    echo "[build_one] ERROR: KPATH not found: $KPATH"
    exit 2
fi

# ============================================================
# 从 Makefile 读取 TCP_ECN_FEATURE 和 OUT_DIR（唯一来源）
# ============================================================
MK_OUT_DIR=$(make -s -f Makefile -p 2>/dev/null | awk -F' := ' '/^OUT_DIR :=/{print $2; exit}')
MK_ECN=$(make -s -f Makefile -p 2>/dev/null | awk -F' = ' '/^TCP_ECN_FEATURE =/{print $2; exit}')
MK_OUT_DIR=${MK_OUT_DIR:-output}
MK_ECN=${MK_ECN:-0}

OUT_DIR="$MK_OUT_DIR"
KO="$OUT_DIR/osec_base.ko-$KVER"
LOG="$PWD_DIR/build_one.$KVER.log"
LOG_ALL="$PWD_DIR/build_all.log"

mkdir -p "$OUT_DIR"
: > "$LOG"
: >> "$LOG_ALL"

# ============================================================
# 按 KVER 选 GCC：候选列表从上到下取第一个环境里存在的
# ============================================================
pick_cc() {
    local kver="$1"
    local candidates=()
    case "$kver" in
      6.8*|6.6*|6.5*|6.2*|6.1*|6.0*)
        candidates=(gcc-13 gcc-12 gcc-11 gcc) ;;
      5.19*|5.18*|5.16*|5.15*|5.14*|5.13*|5.11*|5.10*)
        candidates=(gcc-12 gcc-11 gcc-13 gcc) ;;
      5.4*|5.3*)
        candidates=(gcc-11 gcc-12 gcc-9 gcc) ;;
      4.*)
        candidates=(gcc-9 gcc-11 gcc-12 gcc) ;;
      3.*|2.*)
        candidates=(gcc-9 gcc-11 gcc) ;;
      *)
        candidates=(gcc gcc-12 gcc-11 gcc-13 gcc-9) ;;
    esac
    local c
    for c in "${candidates[@]}"; do
        if command -v "$c" >/dev/null 2>&1; then
            echo "$c"
            return 0
        fi
    done
    return 1
}

if [ -z "${CC:-}" ]; then
    CC=$(pick_cc "$KVER") || true
fi
if [ -z "${CC:-}" ] || ! command -v "$CC" >/dev/null 2>&1; then
    echo "[build_one] ERROR: no usable GCC for $KVER (set CC=... or install gcc)" | tee -a "$LOG" >> "$LOG_ALL"
    exit 2
fi
export CC

echo "[build_one] KVER=$KVER KPATH=$KPATH OUT_DIR=$OUT_DIR (Makefile TCP_ECN_FEATURE=$MK_ECN) CC=$CC" | tee -a "$LOG" >> "$LOG_ALL"

# ============================================================
# 单次编译尝试
# 注意：make 不传 TCP_ECN_FEATURE，让 Makefile 用自己的值
# ============================================================
try_build() {
    local attempt="$1"
    echo "===== [$KVER] attempt $attempt (CC=$CC) =====" | tee -a "$LOG" >> "$LOG_ALL"

    if ! bash clean.sh "$KPATH" >>"$LOG" 2>&1; then
        echo "[build_one] clean failed for $KVER" | tee -a "$LOG" >> "$LOG_ALL"
        return 1
    fi

    rm -f "$KO"

    if make KPATH="$KPATH" CC="$CC" >>"$LOG" 2>&1; then
        if [ -f "$KO" ] && [ -s "$KO" ]; then
            return 0
        else
            echo "[build_one] make ok but $KO missing/empty" | tee -a "$LOG" >> "$LOG_ALL"
            return 1
        fi
    else
        echo "[build_one] make failed for $KVER" | tee -a "$LOG" >> "$LOG_ALL"
        return 1
    fi
}

# ============================================================
# 第一次
# ============================================================
if try_build 1; then
    rm -f "$LOG"
    echo "[build_one] OK   $KVER -> $KO" | tee -a "$LOG_ALL"
    exit 0
fi

# ============================================================
# 失败重试一次
# ============================================================
echo "[build_one] retry $KVER once ..." | tee -a "$LOG" >> "$LOG_ALL"
if try_build 2; then
    rm -f "$LOG"
    echo "[build_one] OK   $KVER -> $KO (after retry)" | tee -a "$LOG_ALL"
    exit 0
fi

# ============================================================
# 两次都失败：保留日志 + 打印关键错误
# ============================================================
echo "[build_one] FAIL $KVER (log kept: $LOG)" | tee -a "$LOG_ALL"
echo "----- key errors for $KVER -----" | tee -a "$LOG_ALL"
grep -nE "not found|No such file|undefined|Error [0-9]+|error:" "$LOG" | tail -n 30 | tee -a "$LOG_ALL" || true
echo "--------------------------------" | tee -a "$LOG_ALL"
exit 1
