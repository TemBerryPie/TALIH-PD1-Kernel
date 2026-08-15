#!/bin/bash
# 把构建好的内核 Image 打包成 boot.img (用原厂 header/ramdisk/dtb)
#
# 用法:
#   ./pack_boot.sh [输出名]
#     默认输出 ../boot_test.img
#
# 需要: 上级目录的 TIK/magiskboot, 以及解包好的原厂 header/ramdisk.cpio/dtb
# (位于 ../unpacked/ 或自行用 magiskboot 解包原厂 boot.img 获得)

set -e

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="${1:-$ROOT/boot_test.img}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

MAGISKBOOT="$ROOT/TIK/magiskboot"
ORIG_BOOT="$ROOT/boot.img"

# 必需文件检查
[ -x "$MAGISKBOOT" ] || { echo "错误: 找不到 $MAGISKBOOT" >&2; exit 1; }
[ -f "$ORIG_BOOT" ] || { echo "错误: 找不到原厂 boot.img ($ORIG_BOOT) 用作打包基准" >&2; exit 1; }
[ -f "$HERE/arch/arm64/boot/Image" ] || { echo "错误: 内核未构建, 先运行 ./build.sh" >&2; exit 1; }

# 准备打包组件: 原厂 header/ramdisk/dtb (来自 unpacked/), 新内核 Image
for f in header ramdisk.cpio dtb; do
    if [ -f "$ROOT/unpacked/$f" ]; then
        cp "$ROOT/unpacked/$f" "$WORK/$f"
    else
        echo "错误: 缺少 $ROOT/unpacked/$f (先用 magiskboot 解包原厂 boot.img 到 unpacked/)" >&2
        exit 1
    fi
done
cp "$HERE/arch/arm64/boot/Image" "$WORK/kernel"

# 用 magiskboot 重组 (它会沿用原厂的 header 参数与压缩格式)
( cd "$WORK" && "$MAGISKBOOT" repack "$ORIG_BOOT" "$OUT" )

echo
echo "===== 打包完成: $OUT ====="
echo "刷入测试: adb reboot bootloader && fastboot flash boot $OUT"
