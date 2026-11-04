# lumia-iris-notes

Static reverse-engineering notes for the **Lumia 950 XL (cityman) Windows Hello iris camera**,
written to support [andrew-lE2A/LumiaFaceID](https://github.com/andrew-lE2A/LumiaFaceID), which brings
the iris sensor up on LineageOS 23.2 / Android 16.

This repo does not contain a driver, a kernel patch or a working capture path. It holds findings from
decompiling the original Windows ARM camera drivers with [REA](https://github.com/morluto/rea) and
Ghidra 12.1.4, plus a script that reproduces the decompilation from the public driver package.

## Main lead (updated after LumiaFaceID `3cb4fad`)

Phone tests ruled out the `0xFDA00044` lead below: the select bit was already set. The new lead:

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
