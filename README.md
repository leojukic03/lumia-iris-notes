# lumia-iris-notes

Static reverse-engineering notes for the **Lumia 950 XL (cityman) Windows Hello iris camera**,
written to support [andrew-lE2A/LumiaFaceID](https://github.com/andrew-lE2A/LumiaFaceID), which brings
the iris sensor up on LineageOS 23.2 / Android 16.

It holds findings from decompiling the original Windows ARM camera drivers with
[REA](https://github.com/morluto/rea) and Ghidra 12.1.4, a script that reproduces the decompilation
from the public driver package, and, in [`android/`](android/README.md), experimental pieces that
make the iris a third Android camera. Those are a sensor plugin, kernel/DT patches and a
sensor-list patch, plus `iris_capture` to take a RAW frame from the iris. On the phone the iris
now streams through the standard Android camera stack (see below).

## Next step: iris as `camera@2` ([`android/`](android/README.md))

The port's front-camera plugin (`camera-sensors/vs6955` in giannoccarol/android_device_msft_cityman)
is built from C against an independently specified angler ABI header, so the missing Qualcomm
`sensor_lib.h` is not needed. `android/` adds a matching `libmmcamera_ir0861` plugin. Its program is
generated from LumiaFaceID's private profile. It also adds the three verified fixes as permanent
kernel/DT patches and a same-length sensor-list patch (`ov4688` → `ir0861`).

## Status (after LumiaFaceID `83e40ed`): the iris streams through Android's camera stack

With our kernel patches 0001–0003, the `ir0861` plugin and the sensor-list patch, the iris is a normal
Camera2 device. Runs of 554 and 335 capture results, CSID3 at 609,014 and 371,690 packets, zero
ECC/CRC, patch 0004 not needed. The picture is gray and noisy and no IR light was used yet. Details and
open points (RAW instead of YUV, IR frame, mount angle): [FINDINGS.md section 19](FINDINGS.md#19-first-frames-through-the-standard-android-stack-lumiafaceid-83e40ed).

## Sensor info (after LumiaFaceID `6404ee0`): taken from the DCC, not the sensor

The sensor's gain/pedestal/pixel-order/strobe-capability registers all read `0x0000`. Windows has
the same problem and solves it in `cam_drv_SMIApp_read16`, which overrides reads with DCC block 5.
That gives `gain = code / 56` (codes 56–448 = 1×–8×) and coarse margin 6, which are now in the plugin.
The strobe capability reads 0 with no override. With that, the driver does not use the sensor strobe:
it arms a CCI hardware sequence that exists only for model `0x861` (FINDINGS section 21). See
[FINDINGS.md section 18](FINDINGS.md#18-sensor-info-reads-0-on-the-phone-windows-takes-it-from-dcc-block-5).

## Status (after LumiaFaceID `d19ac43`): iris CSI packets received

With the three fixes found here (`camss_csi3phy_clk`, regulator load votes, combo lane MISC1 bit 1),
CSID3 received **12,677 and 12,720 iris packets** in two runs, with zero ECC/CRC. The baseline on the
same boot gave 0. The packet count fits about 11–12 full 1088-line frames. No image has been captured
yet. See [FINDINGS.md section 14a](FINDINGS.md#14a-confirmed-on-the-phone-lumiafaceid-d19ac43).

## Combo lane MISC1 bit 1 (confirmed)

Regulator load votes put L17/L3/S3 into HPM, but the iris still delivers zero packets. The remaining
gap is PHY2's upper combo lanes, which the front-camera control did not exercise:

> In combo mode, the original driver writes lane `MISC1` = **`0x06`** (lane 3, clock) and **`0x0A`**
> (lane 4, data). Linux writes `0x04` and `0x08`. The difference is bit 1, set only on the upper
> combo lanes. In non-combo mode, Linux and Windows agree on every lane.

Suggested one-shot: after Linux lane config, write those two values and read them back. See
[FINDINGS.md section 14](FINDINGS.md#14-combo-upper-lanes-windows-sets-bit-1-in-lane-misc1-linux-does-not).

## Earlier lead (after LumiaFaceID `3ea51c1`): regulator load (tested: real, not sufficient)

The `camss_csi3phy_clk` lead below was confirmed on the phone. With that gate added to CSID3, the
working front camera routed to CSID3 went from 0 to 416 frames. The iris still sends nothing, and its
own frame counter `0x0005` never moves, so the remaining problem is on the sensor side.

> Windows votes **300 mA on L17 (vana)** and **80 mA on L3 (vdig)** for the iris. The iris diagnostic
> only calls `regulator_enable()`, with no load. With `qcom,hpm-min-load = 10 mA`, the RPM keeps those
> LDOs in **low-power mode**. The Linux front camera sets 300 mA on the same L17.

That fits a sensor that answers CCI and accepts `0x0100=1` but never finishes a frame. The fix to try
is `regulator_set_optimum_mode()` with the Windows values. See
[FINDINGS.md section 13](FINDINGS.md#13-result-of-section-11-and-the-next-lead-regulator-load-ldo-hpm-vs-lpm).

## Confirmed lead (after LumiaFaceID `3cb4fad`)

Phone tests ruled out the `0xFDA00044` lead below: the select bit was already set. The next lead:

> For the iris, Windows (ACPI `CAMT`) enables **`camss_csi3phy_clk`**. The clock follows the CSID number,
> not the PHY number. The downstream Linux DT gives PHY2 only `camss_csi2phy_clk`, and the recorded
> Linux runs show **`camss_csi3phy_clk` disabled**.

That fits both the iris result and the front camera failing on CSID3, while CSID3's internal test
generator works. Suggested one-shot: the current trial plus `camss_csi3phy_clk` enabled. Details are in
[FINDINGS.md section 11](FINDINGS.md#11-camss_csi3phy_clk-windows-enables-it-for-the-iris-linux-leaves-it-off).

That clock cannot explain why the **sensor's own** frame counter `0x0005` stays at 0. That points at a
second, sensor-side problem. One read of `0x0005` before stream-on tells which case it is, and
`BOOST_BYPASS1_B` is the remaining power difference. See
[section 12](FINDINGS.md#12-the-sensors-own-frame-counter-a-second-sensor-side-problem).

### Earlier lead (ruled out on the phone)

LumiaFaceID's commit `e7e62a3` showed that CSID3 records **no lane events** even with the working front
sensor routed to it, while CSID2 works. Given that result:

> When the iris sensor activates, Windows sets **`0xFDA00040[5:4] = 3` and `0xFDA00044[1] = 1`** in
> CAMSS TOP. The pinned Linux kernel only maps `csiphy_clk_mux` as `<0xfda00040 0x4>` and **never writes
> `0xfda00044`**.

On Windows, CSID3 is also only ever fed through the PHY2 *upper* (combo) field. A front-camera test
through the *lower* field therefore uses a route Windows never uses.

This was checked on the phone: `0xfda00044` read `0x03` before and during the iris run. The original
text and the exact field table remain in
[FINDINGS.md](FINDINGS.md#clock-mux-platform-driver-qccamplatform8994sys-windows-writes-0xfda00044-linux-does-not).

## Other findings

| Topic | Result |
| --- | --- |
| Unpause callback / `0x0c01` path | Same conclusion as the owner's own audit: logging callback, and a mechanical-shutter path that does not apply to iris |
| Sensor OTP "NVM config" writes | Windows applies per-module register writes from the sensor's OTP before streaming. The entry format is decoded |
| CSIPHY settle | Windows uses `100 ns + 4 DDR clock periods` in PHY timer ticks. `0x14` covers only the 100 ns part |
| Iris vs front sensor driver | Same code (171/171 matched functions identical); differences are data only |
| IR illuminator | PMIC flash LED. The original driver's power levels, pulse clamps and cooldown are listed |
| CameraAuthentication.dll | Frame provider with eye-ROI exposure control and per-frame IR pulse. It is not a matcher |

Everything here is **static analysis**. Nothing in this repo was run on a phone. Addresses refer to
the exact driver hashes below.

## Reproduce

Requirements: macOS or Linux, Node.js ≥ 26.12.1, JDK 21+, Ghidra **12.1.4**
(on Apple Silicon build its natives with `support/gradle/gradlew buildNatives`),
and REA (`npm install -g rea-agents`).

```sh
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC
export JAVA_HOME=/path/to/jdk
./scripts/fetch_and_decompile.sh ./work
```

The script downloads the drivers from
[WOA-Project/Lumia-Drivers @ `b5af93f9`](https://github.com/WOA-Project/Lumia-Drivers/tree/b5af93f99ea800c28551727df55e57a07ba61a82/components/QC899X/Hardware/HARDWARE.CAMERA.MMO_8994/Drivers/Camera)
and refuses any file whose SHA-256 differs. It then writes per-function pseudocode to
`work/pseudo-<name>/functions/<address>.c`. The `work/` directory is git-ignored.

| File | SHA-256 |
| --- | --- |
| `Sensors/Iris/arm/qccamsensor_tertiarySMIApp8994.sys` | `0ea99897a1623afd7f165aa2943f2f69687c31dc42a123d6d21c2339ca8e78e5` |
| `Sensors/Front/arm/qccamfrontsensor_secondarySMIApp8994.sys` | `febebc6290b30366c24e6a0a7b50c893dd3602bd11cdf2bc117098114696ce30` |
| `Platform/arm/qccamplatform8994.sys` | `6ae3eb8078998b3d4e75200c671b90c5e5f385168014c70465941bfad4e90aa2` |
| `Flash/Tertiary/arm/qccamflashtertiary8994.sys` | `58cf8c49d30756a5ddae896cf51aa1dd1ae2733217ee603aebacb44ce047c1c5` |
| `Authentication/arm/CameraAuthentication.dll` | `5e7be37803a0573727ea309a52d5f5e6569875485951ec56023f5d9175b5cd4e` |
| `ISP/arm/qccamisp8994.sys` | `0673448ca7b96c75fcb6ba7c4f50985e16e9f0a1b21b547fb37617f5ad60d78d` |
| `Core/arm/qccamcore8994.sys` | `d00cf6238c5885e45e89fb908c7dcf587fbab22a23eda1f650acb0d9e8cba415` |

## What is not here

No Windows binaries, calibration files, full decompiler output or biometric data are distributed.
Only findings, short excerpts and addresses are included. The binaries are fetched from their public
source when you run the script.

Analysis is for interoperability research on hardware you own.
