# tb8788p1_64_wifi 内核源码 (MT6771)

适用于 **Chuwi HiPad Plus / 创维 Swaiot AIP10A / 读书郎 C13 Pro / SUPI T11** 等
`tb8788p1_64_wifi` 公版平板 (MediaTek MT6771 / Helio P60, PMIC MT6358)。

- 内核版本: **4.14.186** (与原厂完全一致, vermagic 匹配原厂 vendor 模块)
- 基础源码: `ubuntu-touch-unihertz-titan/kernel-alps-mt6771` (完整 alps-mp-r0 BSP)
- 编译链: clang 11.0.1 r383902 (与原厂构建版本完全相同)

---

## 一、构建 (GitHub Actions)

```bash
git push origin main        # push 即触发构建
# 或网页: Actions → build-kernel → Run workflow
```

产物: Actions 页 `build-kernel` run 的 **artifact `Image-TALIH-PD1`** (arch/arm64/boot/Image)。

本地构建 (需 clang r383902 + gcc-aarch64-linux-gnu):

```bash
export PATH="<toolchain>/clang-r383902b/bin:$PATH"
make ARCH=arm64 CC=clang CLANG_TRIPLE=aarch64-linux-gnu- CROSS_COMPILE=aarch64-linux-gnu- -j10 Image dtbs
# KBUILD_KCONFIG 需指向 arch/arm64/Kconfig (MTK 惯例, 顶层无 Kconfig)
```

产物: `arch/arm64/boot/Image` (≈25MB), `arch/arm64/boot/dts/mediatek/mt6771.dtb`。

## 二、打包 boot.img 并刷入

```bash
./pack_boot.sh                    # 生成 ../boot_test.img (原厂 header+ramdisk+dtb + 新内核)
adb reboot bootloader
fastboot boot ../boot_test.img    # 临时引导测试, 不改分区
# 或
fastboot flash boot_b ../boot_test.img   # 刷入当前槽位 (见 fastboot getvar current-slot)
```

设备 A/B 分区, vbmeta 无锁无校验 (用户已确认)。

## 三、模块兼容性 (已离线验证)

新内核与原厂 vendor 模块完全 ABI 兼容:
- vermagic 精确一致: `4.14.186-g08d3400dc4c7-dirty SMP preempt mod_unload modversions aarch64`
- 7 个原厂模块 (wlan_drv_gen3 / bt / gps / fmradio / fpsgo / met / kheaders) 期望的
  内核符号 **CRC 零不符**; 缺失的 `mtk_wcn_*` connsys 符号由原厂 `wmt_drv.ko` 自导出。
- 上机实测: 上述模块全部正常加载, WiFi/蓝牙/GPS 工作正常。

## 四、各部件移植/修复说明

| 部件 | 状态 | 说明 |
|------|------|------|
| 显示 | ✅ 正常 | 根因是 `dsi.mode` 误用 `BURST_VDO_MODE`; 经**反汇编原厂内核 get_params** 提取真实参数(`SYNC_PULSE_VDO_MODE`, cont_clock=1, vsa=8/vbp=28/vfp=103, hsa=14/hbp=28/hfp=42, PLL=746), 并用**从 LK 二进制提取的 81 条原厂 init 序列** 初始化面板。 |
| 背光/息屏唤醒 | ✅ 正常 | resume 崩溃根因: `ktz8864a` 电源/背光 IC 无 dts 节点导致 i2c 客户端为 NULL, resume 时 `ktz8864a_write_byte → i2c_master_send` panic。已加 NULL 保护 (LK 已初始化电源, resume 跳过写)。 |
| WiFi/蓝牙/GPS/FM | ✅ 正常 | 用原厂 vendor 模块即可 (ABI 兼容, 见上)。 |
| 电池/充电 | ✅ 正常 | MT6358 gauge/charger + 板级 battery profile (dtb)。 |
| 相机 | ✅ 内核侧正常 | `s5k3l6_mipi_raw` 传感器驱动 (Micromax 版适配 v1_1 API), camera_main/sub 在 i2c 上探测并绑定 `kd_camera_hw`。`s5k3l7` 用占位 stub (无公开源码)。相机 HAL 是 GSI userspace 问题, 非内核。 |
| 触摸 | ⚠️ 卡在安全模式 | 见下节。 |

## 五、触摸 (HX83102P incell, SPI) 现状

**已打通**: 芯片检测(hx83102e)、坐标 1600×2176、触摸固件下载
(`/vendor/firmware/Himax_firmware_spi.bin`, 版本 0xD204 与原厂一致)、IRQ18 注册、
IC 信息读取, 且**触摸寄存器配置与原厂逐项一致**。

**未通**: 触摸 FW 处于**安全模式** (`cs_central_state != 0x05`), 能报版本但不扫描、
不产出数据 (sram 读取失败, 事件栈只出 4 字节片段导致 checksum 失败)。
官方 Himax 参考驱动 (HimaxSoftware HX83112/incell) 的安全模式释放机制
(写 0x53 到 0x90000098) 对本芯片不生效 (cs_state 不变)。

**原因**: 这是**固件安全模式退出/TDDI 扫描使能**的问题, 需要原厂
`elink/hxchipset_spi` 触摸驱动的确切机制 (该源码公开渠道确认没有, 见下"源码线索")。
触摸驱动本身已编译进内核并正常工作到"检测到芯片"这一步。

## 六、对源码树所做的修改 (相对上游)

1. 顶层 `Makefile`: 默认 `MTK_PLATFORM=mt6771` + `MTKINCLUDES` 全局 include 路径
   (alps 跨模块尖括号引用; 542 个 MTK Makefile 依赖 `$(MTK_PLATFORM)`)。
2. 顶层无 `Kconfig` (MTK 惯例): 构建需 `KBUILD_KCONFIG=arch/arm64/Kconfig` (build.sh 已处理环境)。
3. 补齐上游漏传的 `init/Kconfig` 及 408 个缺失 Kconfig (从 gregkh/linux v4.14.186 恢复)。
4. `drivers/devfreq/Makefile`, `drivers/extcon/mediatek/Makefile`,
   `drivers/mmc/host/mediatek/ComboA/Makefile`: 补 `-I` 本地头文件路径。
5. `drivers/misc/mediatek/accdet/mt6358/accdet.c`: 修复全配置关闭时的条件编译语法错误 + 未用变量。
6. `drivers/devfreq/helio-dvfsrc.c`: 修正笔误的尖括号 include (引号, 用本地 mtk_dvfsrc_reg.h)。
7. LCM: 新建 `hx83102p_2082110afh036002_53c` 与 `tv110xum_lb2_incell_v2` 面板驱动
   (同 IC 模板适配, 1600×2176, 已注册进 `lcm_driver_list`), `.name` 去后缀以匹配 LK 上报;
   `get_params` 用反汇编提取的原厂时序; init 用 LK 提取的 81 条序列。
8. 传感器: `s5k3l6_mipi_raw` (去 OPPO 依赖/适配 tag 风格 enum/删 SensorModuleName/OtpID);
   `s5k3l7_mipi_raw` 占位 stub。
9. 触摸: 移植 `hxchipset_spi` (GS290-dev) + mtk_tpd 框架补 `elink,touch` 匹配 +
   SPI 引脚功能配置(_h 状态) + `mediatek,spi_himax_touch` of_match + 中断从 SPI 设备节点解析
   + 坐标改 1600×2176 + 固件名改 `Himax_firmware_spi.bin` + GTP_RST_PORT=158。
10. `drivers/input/touchscreen/mediatek/mtk_tpd.c`: `touch_of_match` 增加 `elink,touch`。

## 七、源码线索 (供继续完善触摸)

- 公版方案整机: Chuwi HiPad Plus / 创维 Swaiot AIP10A / 读书郎 C13 Pro / SUPI T11
- 公开固件 dump: `r0rt1z2-dumpyard/chuwi_hipadplus_dump` (同板 tb8788p1_64_wifi,
  含 boot/vendor/dtbo, 可提取触摸固件与 dtb, 无内核源码)
- 触摸驱动为 `drivers/input/touchscreen/elink/hxchipset_spi/` (elink 定制),
  显示驱动为 `elink_lcm`, 可能在代工厂/方案商源码中。
- Himax 官方参考: `HimaxSoftware/HX83112_Android_Driver` (incell 实现参考)。

## 八、KernelSU (SukiSU Ultra) 集成

- 驱动: **SukiSU Ultra main (driver 40877)**, 4.14 全面适配
  (LSM/patch_memory/selinux/file_wrapper/fsnotify 等 compat + path_mount/path_umount backport)
- **SUSFS v2.2.0** (gki-6.12 特性集移植): sus_map / avc_log_spoofing / sus_path_loop /
  hide_sus_mnts / sdcard_monitor / enabled_features; CMD dispatch 经 reboot SUSFS_MAGIC
- 4.14 关键适配: MTK el0_svc 直接 blr (syscall 表参数版) → `ksu_syscall_table_call()` wrapper;
  4.14 无 seccomp action-cache → `disable_seccomp()` 路径; `CONFIG_FTRACE_SYSCALLS=y` 必须开;
  reboot/input kprobe handler 用直接参数
- Manager 显示 `v4.1.3-TALIH-PD1@Fumor` (KSU_VERSION_FULL 在 Kbuild 写死)

## 九、已知次要问题

- `hx83102p_fhdp_dsi_vdo_boe` platform driver 名在两个面板拷贝中重复
  (第二次注册 abort, 不影响 hx83102p 主面板)。
- s5k3l7 相机传感器无公开源码 (占位 stub), 设备若装配的是 s5k3l6 则相机可用。
- **WiFi/蓝牙 (二分进行中)**: 原厂 boot 下正常; 本内核下 TEE 报 BTA TA "No such object
  found" (93feffcc...) + activation data len 0, 蓝牙 HciHalHidl 启动失败。当前在
  SUSFS on/off 二分定位 (Actions 默认构建为 SUSFS-off 测试配置)。
- 元模块 (Hybrid Mount/mountify/meta-overlayfs) 与 GSI 兼容性差: overlay 依赖
  /system/bin symlink (GSI 为真目录) 或 5.x 内核 API; 固化类模块建议 magic bind
  或合并进稳定模块 (hwid) 的 workaround。
