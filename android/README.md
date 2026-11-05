# Iris as a third Android camera (works on the phone, image quality unresolved)

Drop-in pieces to make the iris sensor a normal camera (`camera@2`) on the cityman LineageOS port, so
the standard Qualcomm stack (`mm-qcamera-daemon` → ISPIF → VFE) delivers frames. They follow the
port's own front-camera plugin:
[giannoccarol/android_device_msft_cityman](https://github.com/giannoccarol/android_device_msft_cityman)
`lineage-23-cityman`, `camera-sensors/vs6955/`. That plugin is built from C against
`camera-sensors/imx230/angler_sensor_abi.h`, so **the missing `sensor_lib.h` is not needed**.

On the phone (LumiaFaceID `83e40ed`) the plugin probes, the iris appears as a third camera, and
Camera2 streams it with clean CSID3 packets (FINDINGS section 19). The receiver settings were first
verified in LumiaFaceID `d19ac43`:
with `camss_csi3phy_clk`, regulator load votes and MISC1 `0x06`/`0x0A`, CSID3 received 12,677 and
12,720 iris packets with no ECC/CRC errors. The pieces below turn exactly those settings into the
standard path.

## Files

| File | Goes to | Purpose |
| --- | --- | --- |
| `camera-sensors/ir0861/sensor_lib_ir0861.c` | device tree `camera-sensors/ir0861/` | Plugin descriptor: CCI 0x6c, ID `0x0000 = 0x0861`, CAMT power order, 1920×1088 RAW10, one lane, PHY2 combo `0x18` → CSID3, settle 22, imx179 chromatix seeds |
| `camera-sensors/ir0861/generate-ir0861.py` | same | Turns LumiaFaceID's private `cityman-iris-stream-profile.hex` (program SHA-256 `754786…8eb5`) into `ir0861_registers.generated.h` (87 idle + 30 mode writes) |
| `camera-sensors/ir0861/Android.mk` | same | `libmmcamera_ir0861` (32-bit vendor), only with `CITYMAN_CAMERA_IRIS=true` |
| `tools/patch-sensor-list-ir0861.py` | device tree `tools/camera-a13/` | Replaces the unused `ov4688` entry in the daemon's sensor list with `ir0861` (same length) |
| `tools/iris-capture/` | device tree `tools/iris-capture/` | `iris_capture`: opens one explicit Camera2 ID through the NDK, flash forced off, saves a few frames with min/max/mean. `raw_to_pgm.py` turns a frame into a viewable PGM |
| `kernel/0001-msm_csiphy-set-bit1-on-upper-combo-lanes.patch` | kernel | Permanent MISC1 fix: lane 3 `0x4 → 0x6`, lane 4 `0x8 → 0xA` in combo mode only |
| `kernel/0002-msm8994-camera-csid3-csi3phy-clock.patch` | kernel | `camss_csi3phy_clk` on CSID3 (the CSID3 half of LumiaFaceID's tested experiment patch) |
| `kernel/0003-camera-cityman-add-iris-camera-slot.patch` | kernel | `qcom,camera@2`: CSIPHY2/CSID3, MCLK1/GPIO14, reset GPIO102, L17/LVS1/S3/L3 with `cam-vreg-op-mode = <300000 0 300000 80000>`. Ships `status = "disabled"` |
| `kernel/0004-optional-msm_csid-csid3-core-ctrl1-bit16.patch` | kernel | Optional, see below |

All patches were checked with `patch -p1 --dry-run` against kernel `cc84cab9`. 0003 uses the pin
groups `cityman_iris_reset_active/sleep` from LumiaFaceID's `0002-cityman-iris-id-integration.patch`.
The plugin was compiled with `clang --target=armv7a-linux-androideabi -Wall -Wextra -Werror` against
the port's ABI header, and all of the header's ARM32 size/offset `_Static_assert`s pass.

## Steps

0. **Sensor info: done, no phone step needed.** The original driver reads gain, black level and
   pixel order at start-up (`0x40f374`, `0x4107f8`). LumiaFaceID `6404ee0` read them on the phone,
   and every one is `0x0000`. That is expected. Windows reads them through
   `cam_drv_SMIApp_read16` (`0x40ee00`), which replaces the result with the matching record from
   DCC block 5 (`OVERRIDE`, "read overrides"). The plugin now uses exactly what Windows ends up
   with (FINDINGS section 18):

   | Register | Meaning | Windows value | Macro |
   | --- | --- | --- | --- |
   | `0x0084` / `0x0086` / `0x0088` | gain code min / max / step | 56 / 448 / 1 (block 5) | `GAIN_CODE_MIN/MAX/STEP` |
   | `0x008c` / `0x008e` / `0x0090` / `0x0092` | gain model m0 / c0 / m1 / c1 | 1 / 0 / 0 / 56 | `GAIN_M0/C0/M1/C1` |
   | `0x1006` | coarse integration max margin | 6 (block 5) | `COARSE_MARGIN` |
   | `0x0008` | data pedestal | 0 (sensor, no override) | `PEDESTAL` |
   | `0x0006` | pixel order | 0 = GRBG (sensor, no override) | `PIXEL_ORDER_CCS` |

   So `gain = code / 56`, which gives 1×–8×. Orientation: Windows writes `0x0101 = 0`, unless the OEM
   registry key `Rotation\FlipMirror` is 1, which gives `3`. That registry value is not public.
1. **Kernel:** apply 0001–0003 and set `qcom,camera@2` to `status = "ok"` for the test build. The
   front camera keeps working: 0001 only changes combo mode, and 0002 only adds a clock to CSID3.
2. **Plugin:** copy `camera-sensors/ir0861/` into the device tree and build:
   ```sh
   export CITYMAN_CAMERA_IRIS=true
   export CITYMAN_CAMERA_IRIS_PROFILE=$HOME/Documents/cityman-iris-stream-profile.hex
   m libmmcamera_ir0861
   ```
   Push `/vendor/lib/libmmcamera_ir0861.so`.
3. **Sensor list:** run the patch script on a copy of `/vendor/lib/libmmcamera2_sensor_modules.so`
   (expects the shipped vs6955-patched file, SHA-256 `2d14928f…ec1b`), then bind-mount or install
   it the same way as for vs6955.
4. **Boot** with `fastboot boot`. Look for `ir0861 probe succeeded` in `dmesg`, and check that the
   camera list grows to three.

   Done in LumiaFaceID `84e228b`: probe succeeded (`read id 0x861`), and there are three cameras.
   The iris has a **different ID from boot to boot** (2 on a temporary boot, 1 once flashed), so
   find it by its 1920×1088 pixel array, never by number.
5. **Streaming works** (LumiaFaceID `83e40ed`, Camera2 YUV). **`iris_capture` takes a RAW frame**,
   which avoids the ISP treating a mono sensor as Bayer. Without `-c` it picks the unique 1920×1088
   camera:
   ```sh
   m iris_capture
   adb root
   adb push $OUT/system/bin/iris_capture /data/local/tmp/
   adb shell /data/local/tmp/iris_capture -l
   adb shell /data/local/tmp/iris_capture -n 5 -t 10
   ```
   `-l` lists every camera with its formats. The
   capture prefers RAW10, then RAW16, then YUV (`-f` forces one). It prints one line per frame and
   writes `/data/local/tmp/iris-N.<format>`. Run it as root, because cameraserver grants the CAMERA
   permission to uid 0. The flash is forced off. If AE never converges, `-e 30000 -s 100` gives a fixed
   30 ms exposure. If a frame arrives:
   ```sh
   adb pull /data/local/tmp/iris-0.raw10
   python3 tools/iris-capture/raw_to_pgm.py iris-0.raw10 iris-0.pgm --format raw10 \
       --width 1920 --height 1088 --stride <stride from the log> --stretch
   ```
   If no frame arrives, read the CSID3 packet count from the same run. With zero packets and the
   diagnostic still getting packets on the same boot, apply 0004. With packets but no SOF, check the
   ISPIF select bits below.

## Things to watch

- **Which ID is the iris.** The HAL sorts cameras back first, then front. The plugin reports the
  iris as front-facing, so it may come out as ID 1 or 2. Check `dumpsys media.camera` or the
  daemon log for the sensor name before testing.
- **Never stream the iris and the front camera at the same time.** Both use CSIPHY2. The front
  uses it in normal mode, the iris in combo mode.
- **The `cityman-iris-id` diagnostic node owns the same GPIO102/MCLK1.** Do not run the diagnostic
  while the iris camera is open.
- **CSID3 `CORE_CTRL_1` bit 16.** The verified packet runs used LumiaFaceID's diagnostic, which writes
  `0x0005000f` (bit 16 set, as Windows does). The standard `msm_csid.c` writes `0x0004000f`. If the
  standard path counts zero packets on CSID3 while the same boot's diagnostic counts packets, apply
  0004. It sets bit 16 only for CSID3.
- **The image will be dark.** The plugin starts at 1000 lines (≈ 30 ms). AEC with imx179 chromatix
  will then drive it. There is no IR illumination yet, so aim at sunlight, a bulb or a TV remote.
  Getting a frame through Camera2 RAW (for example the port's `cityman-camera` DNG mode) avoids
  colour processing of what is probably a monochrome sensor.
- **ISPIF select bits** (FINDINGS section 15). If the CSID counts packets but the VFE never reports
  SOF, read `0xfda00020/24/28/2c`.
- **Still placeholders after step 0:** mount angle (check on the first image), lens data and tuning.

## Licence and credits

The files here are GPL-2.0-only, like the vs6955 plugin and the tools they follow. The plugin
structure, ABI header and sensor-list approach are by giannoccarol (cityman port). The iris register
program, profile format and all phone measurements are from andrew-lE2A/LumiaFaceID. No vendor
binary or register table is included.
