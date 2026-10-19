#!/bin/bash
# usage: bash build_one.sh <KVER> <KPATH> [out_dir]
# 成功: 产物在 <out_dir>/osec_base.ko-<KVER>，删除单版本日志，返回 0
# 失败: 保留 build_one.<KVER>.log，返回 1
# 说明:
#   - 若调用方 export CC=xxx，则尊重调用方；
#   - 否则按 KVER 从候选列表里选“环境里实际存在的 GCC”；
#   - 候选列表每个分支最后都有 gcc 兜底，所以只装了 gcc（如 4.8.5）的容器也能编。
set -u

KVER="$1"
KPATH="$2"
OUT_DIR="${3:-output_ecn}"
PWD_DIR="$(pwd)"
KO="$OUT_DIR/osec_base.ko-$KVER"
LOG="$PWD_DIR/build_one.$KVER.log"
LOG_ALL="$PWD_DIR/build_all.log"

if [ -z "${KVER:-}" ] || [ -z "${KPATH:-}" ]; then
    echo "usage: bash build_one.sh <KVER> <KPATH> [out_dir]"
    exit 2
fi
if [ ! -d "$KPATH" ]; then
    echo "[build_one] ERROR: KPATH not found: $KPATH"
    exit 2
fi

mkdir -p "$OUT_DIR"
: > "$LOG"
: >> "$LOG_ALL"

# ============================================================
# 按 KVER 选 GCC：候选列表从上到下取第一个环境里存在的
# 每个分支最后都有 gcc 兜底，只有 gcc 的容器也能选到
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

# 调用方已 export CC 则尊重；否则自动选
if [ -z "${CC:-}" ]; then
    CC=$(pick_cc "$KVER") || true
fi
if [ -z "${CC:-}" ] || ! command -v "$CC" >/dev/null 2>&1; then
    echo "[build_one] ERROR: no usable GCC for $KVER (set CC=... or install gcc)" | tee -a "$LOG" >> "$LOG_ALL"
    exit 2
fi
export CC

echo "[build_one] KVER=$KVER KPATH=$KPATH OUT_DIR=$OUT_DIR CC=$CC" | tee -a "$LOG" >> "$LOG_ALL"

# ============================================================
# 单次编译尝试：clean -> rm 旧产物 -> make -> 校验产物
# ============================================================
try_build() {
    local attempt="$1"
    echo "===== [$KVER] attempt $attempt (CC=$CC) =====" | tee -a "$LOG" >> "$LOG_ALL"

    if ! bash clean.sh "$KPATH" >>"$LOG" 2>&1; then
        echo "[build_one] clean failed for $KVER" | tee -a "$LOG" >> "$LOG_ALL"
        return 1
    fi

    # 删旧产物，防止“上次残留”冒充本次成功
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
# 失败重试一次（残留软链/临时文件导致的偶发失败）
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
