#!/bin/bash
# tb8788p1_64_wifi (Chuwi HiPad Plus / 创维/读书郎公版, MT6771) 内核构建脚本
#
# 用法:
#   ./build.sh            # 全量构建 Image + dtb
#   ./build.sh clean      # 清理构建产物
#
# 说明: 本源码树基于 ubuntu-touch-unihertz-titan/kernel-alps-mt6771 (alps 4.14.186)
# 已移植适配 tb8788p1 (面板/触摸/传感器/defconfig/修复)。

set -e

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

# 编译工具链: 与设备原厂内核完全同版本 clang 11.0.1 (r383902)
CLANG_DIR="$(cd "$HERE/../../toolchain/linux-x86/clang-r383902" 2>/dev/null && pwd)"
if [ ! -x "$CLANG_DIR/bin/clang" ]; then
    # 兼容把 toolchain 放到别处的情形
    CLANG_DIR="${CLANG_R383902_DIR:-$HERE/../toolchain/linux-x86/clang-r383902}"
fi
if [ ! -x "$CLANG_DIR/bin/clang" ]; then
    echo "错误: 找不到 clang-r383902 工具链 (期望在 $CLANG_DIR)" >&2
    echo "请把 toolchain/linux-x86/clang-r383902 放到 kernel/ 上级目录, 或设置 CLANG_R383902_DIR" >&2
    exit 1
fi
export PATH="$CLANG_DIR/bin:$PATH"

JOBS="${JOBS:-$(nproc)}"

MAKE_ARGS=(
    ARCH=arm64
    CC=clang
    CLANG_TRIPLE=aarch64-linux-gnu-
    CROSS_COMPILE=aarch64-linux-gnu-
    LOCALVERSION=
)

DEFCONFIG=tb8788p1_64_wifi_defconfig

if [ "$1" = "clean" ]; then
    make "${MAKE_ARGS[@]}" distclean
    exit 0
fi

if [ "$1" = "defconfig" ] || [ ! -f .config ]; then
    make "${MAKE_ARGS[@]}" "$DEFCONFIG"
fi

# 构建内核镜像与设备树
make "${MAKE_ARGS[@]}" -j"$JOBS" Image dtbs

echo
echo "===== 构建完成 ====="
echo "Image: arch/arm64/boot/Image"
ls -la arch/arm64/boot/Image 2>/dev/null || true
echo "下一步: 用 ../pack_boot.sh 打包成 boot.img 并刷入测试"
