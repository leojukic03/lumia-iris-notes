# Findings: Ghidra/REA pass over the original Windows camera drivers

Target: `qccamsensor_tertiarySMIApp8994.sys` from WOA-Project/Lumia-Drivers @ `b5af93f9`,
SHA-256 `0ea99897a1623afd7f165aa2943f2f69687c31dc42a123d6d21c2339ca8e78e5` (same file as `docs/hardware.md`).
Tooling: REA 6.8.0 `decompile-all` with Ghidra 12.1.4 (ARM Thumb, PE). 363 functions decompiled.
Everything below is static decompiler output, not observed execution. Function names come from the
driver's own trace strings.

**Update after commit `e7e62a3` (front camera gets zero lane IRQs on CSID3):** the strongest lead is now
the **CAMSS TOP select register `0xFDA00044`**, which Windows writes and the Linux kernel never touches
(section 3, "Clock mux"). Suggested order:
(1) read `0xfda00040/0xfda00044` read-only on a working CSID2 stream and during the iris one-shot;
(2) if `0x44[1]` is 0, a one-shot that sets it before stream-on;
(3) read the sensor OTP for `'!'` NVM config entries (section 2);
(4) compute the Windows settle value from the mode's DDR clock (section 3).
Sensor startup (section 1) and front-vs-iris code (section 4) showed no mismatch.

## 1. Unpause (`0x411d4c` = `cam_drv_SMIApp_unpause`): independent cross-check

The owner resolved both open unpause branches independently in `docs/iris-startup-audit.md`
(commit `e7e62a3`). This Ghidra pass reached the same conclusions by a different route (decompiled
trace strings and registration struct). It is included only as a second, tool-based confirmation.

For model `0x0861` (not `0x4141/0x4541/0x560f/0x5623/0x21c7/0x5e80`) the routine does:

1. If `DAT_0083a658 != 0`: apply stored settings slot 15 ("Applying standby exiting register settings").
   The audit already established that DCC `0x0013` is absent, so this slot is empty for this calibration.
2. `0x0100 = 1`, then `0x0138 = 1`.
3. On success, call the optional callback `DAT_0083b368`.
4. If `DAT_00831f08 != 0`: delay, I²C write to slave `0x7c` reg `0x0520 = 0`, delay 50 ms, `0x0c01 = 1`
   ("SENSOR READOUT STARTED"), then clear the flag.
5. Log "SENSOR STREAMING STARTED" and set `DAT_00460d98 = 0`.

**Post-unpause callback (audit item at `0x411e82`): resolved, not hardware-relevant.**
`cam_drv_ctrl_init` (`0x4171e4`) stores init-config slot 10 into `DAT_0083b368`. The caller (`0x40a4d8`)
fills slot 10 (`local_38`) with `0x405c51`, i.e. Thumb function `0x405c50`. That function only emits a
trace event ("Streaming started in still mode") under a lock. It writes no registers.

**Delayed auxiliary path (audit item at `0x411e8a`): resolved, not for normal streaming.**
`DAT_00831f08` is only set to nonzero in `cam_drv_SMIApp_ms_handle` (`0x415ee8`), the mechanical
shutter / global-reset (still capture, flash strobe) handler, and only when `DAT_00460d98 == 1`.
Slave `0x7c` is the OIS controller: the same `0x7c`/`0x0520` writes appear in `cam_drv_SMIApp_ois_config`
(`0x40deec`) and `cam_drv_SMIApp_off` (`0x40c31c`). This is shared SMIA++ code for the main camera.
It is not a missing step for iris viewfinder streaming. **Do not add the `0x0c01` write.**

Net: for `0x0861` the original unpause is just `0x0100=1`, `0x0138=1`, which the diagnostic already does.

## 2. New lead: sensor NVM/OTP "config data" written in `cam_drv_SMIApp_sensor_config` (`0x4165ac`)

After `0x0111=2`, `0x0110=<VC>` and `0x0114=<lanes-1>` (already known), `sensor_config` runs a loop:

```c
FUN_0041b12c(&entry, nvm_cache /*DAT_00831ee4*/, i);  // cam_drv_SMIApp_parser_parse_nvm_config_data
while (entry.len != 0) {
    slave = (entry.dev == ' ') ? sensor_slave /*DAT_00831eef*/ : entry.dev;
    cam_drv_common_i2c_write(slave, entry.reg, entry.addr_len, entry.len, 0, entry.data);
    // trace: "NVM config write8 0x%x = 0x%x"
    ...next entry...
}
```

The NVM cache comes from `cam_drv_SMIApp_cache_nvm` (`0x4140b0`), called from
`cam_drv_SMIApp_read_static_information` (`0x40f1c8`) during `cam_drv_SMIApp_config`. It uses the
standard SMIA++ data-transfer interface: page `0x0a02`, control `0x0a00=1`, status `0x0a01`, data
read from `0x0a04` (pages of 16 bytes, checksum, error-count field), then `0x0a00=4` to finish.

The parser only emits config entries when header byte 1 bit 3 **and** byte 2 bit 4 are set
("sensor does not have NVM config data" otherwise). Base address, size, target page and device
address are logged ("NVM config base_address / data size / device_address / target page").

**Why it matters:** these are per-module register writes stored in the sensor's own OTP, applied
before streaming. They are not in the DCC and not in the extracted 117-byte idle/mode program. If this
module's OTP contains config entries (analog/PLL/MIPI trims, for example), a profile without them
could program and latch mode registers correctly while the MIPI transmitter never starts.

**Suggested discriminating step (read-only on the sensor array):** with the existing one-shot
diagnostic path, read the OTP pages through `0x0a02/0x0a00/0x0a01/0x0a04` exactly as
`0x4140b0` does, save the raw bytes privately, and check the byte 1/2 flags. If config data is
present, decode the entries with the `0x41b12c` layout before considering any write. If it is absent,
this lead is closed.

### 2a. NVM config layout (`cam_drv_SMIApp_parser_parse_nvm_config_data`, `0x41b12c`)

`nvm` is the cached OTP buffer, big-endian fields:

1. Require `nvm[1] & 0x08` and `nvm[2] & 0x10`.
2. Compute a bit offset `off`: start at 13, or 18 if `nvm[1] & 0x80`. Add 5 for each of `nvm[1]` bits
   `0x40`, `0x20`; add 7 for `0x10`; add 12 for each of `nvm[1]` bits `0x04`, `0x02`, `0x01` and
   `nvm[2]` bits `0x80`, `0x40`, `0x20`.
3. `i = 3 + off/8`, `r = off%8`. Config pointer `p = ((nvm[i]<<16 | nvm[i+1]<<8 | nvm[i+2]) >> (12-r)) & 0xfff`.
4. `count = nvm[p]`, entries start at `p+1`:
   - `'!'` (0x21): target = the sensor itself. `reg = BE16(+1)`, `len = BE16(+3)`. If the top nibble of
     `len` is nonzero, `len &= 0x7fff` and the register address is 1 byte; otherwise 2 bytes.
     `len` data bytes follow at `+5` and are written as one burst starting at `reg`.
   - `'|'` (0x7c): target = I²C slave `0x7c` (the OIS device), with `reg = BE16(+1)`, page `=(+3)`,
     `len = BE16(+4)` (same nibble rule), data at `+6`. These are indexed from `0x100` and are **not**
     applied by `sensor_config`.
   - Any other marker: "NVM config data unknown config", stop.

So only `'!'` entries matter for the iris sensor. If the iris OTP has none, this lead is closed.

## 3. Windows-side MIPI/CSI parameters (iris driver `ConfigResolution`, `0x403a10`)

The SMIApp KMD itself computes the CSIPHY parameters it hands to the platform:

```c
timer_hz = (soc_id == 10 || soc_id == 11) ? 177780000.0 : 200000000.0;   // FUN_0041fc34()
ddr_hz   = mode->ddr_clock ? mode->ddr_clock : 1;                          // mode +0x98
settle   = (uint)(((4e9 / ddr_hz + 100.0) * timer_hz) / 1e9 + 0.5);
// trace: "MIPINumOfDataLane = %d, MIPISettleCount in PHYTIMER = %d, MIPIDDRClock = %d"
```

So on Windows the settle time is **100 ns + 4 DDR clock periods**, counted in PHY timer ticks.
The diagnostic's `0x14` (20 ticks at 200 MHz) equals only the 100 ns term. Example: a 200 MHz DDR
clock gives `(20 + 100) * 0.2 = 24 = 0x18`. A 100 MHz DDR clock gives `28 = 0x1c`.
**Compute the value from the iris mode's actual DDR/link clock** (mode table field `+0x98` in the
driver's mode struct; it should be recoverable from the DCC mode). A short settle more often shows up as
ECC/CRC errors than as zero packets, so this is a cheap comparison, not a likely root cause.

The same function sets the PHY mode. With the combo flag (`DAT_00461558 == 1`) and 1 lane it logs
"[CSIPHY Config] ID = %d, PHY Combo (2+1) mode 1 lanes" and marks the property block combo
(`+0x1c4 = 1`, `+0x1c8 = PHY id`). That matches the existing PHY2 combo / CSID3 route.

### Clock mux (platform driver `qccamplatform8994.sys`): **Windows writes `0xFDA00044`, Linux does not**

`SensorDeviceActivate` (`0x41c974`) sends `IOCTL_KMD_CAMERA_PLATFORM_CSI_CLK_MUX_CONFIG` (`0x232027`)
with input `{csid, 0}` (`csid` from the sensor config, valid 1..3, default 2).

The platform IOCTL handler (`0x402510`, decompiles badly, read from disassembly at `0x402ae2`–`0x402cbc`)
builds a list of mux-field indices `k` from `csid`, then `0x10` as terminator:

| `csid` | fields `k` |
| --- | --- |
| 0 | 10, 11 |
| 1 | 12, 13 |
| 2 | 14 |
| 3 | 15 |

(The second input word adds ISPIF fields 0..9 via bits `0x1/0x2/0x4/0x8/0x100..0x2000`. The sensor sends 0.)
Each requested field gets `active = 1`, `select = 1`, `value = csid`. Then `cgc_pre_mux_sel` (`0x40854c`)
and the two writers run. The base is CAMSS TOP: `FUN_00408ec4(3)` returns `DAT_0041c5a4`, which
`0x42e278` maps from the second ACPI `Memory32Fixed` of `CAMP`, i.e. `0xFDA00000`, **length `0x47`**.

- `0x4082b4` (value fields): writes `+0x28` (k 0..5), `+0x20` (k 6..9), `+0x30` (k 10,11), `+0x38` (k 12,13),
  `+0x40` (k 14,15). Each field is 2 bits at bit `4*j`.
- `0x408400` (select/enable bits): writes `+0x2c` (k 0..5), `+0x24` (k 6..9), `+0x34` (k 10,11),
  `+0x3c` (k 12,13), **`+0x44` (k 14,15)**. Each field is 1 bit at bit `j`.

So for the iris (`csid = 3`) Windows sets **`0xFDA00040[5:4] = 3` and `0xFDA00044[1] = 1`**. For a
CSID2 sensor it sets `0xFDA00040[1:0] = 2` and `0xFDA00044[0] = 1`.

The Linux DT gives `csiphy_clk_mux` as `<0xfda00030 0x4>`, `<0xfda00038 0x4>`, `<0xfda00040 0x4>`, and
`msm_csiphy_lane_config` only does a read-modify-write of that one word. **Nothing in the pinned
kernel writes `0xfda00034`, `0xfda0003c` or `0xfda00044`.** (ISPIF's `csi_clk_mux` is `<0xfda00020 0x10>`
and does cover `+0x24/+0x2c`.)

Two consequences:

1. **Candidate root cause.** The `0x40` value nibble the diagnostic sets matches Windows, but the
   companion select bit `0x44[1]` may be 0. If its reset/bootloader state enables only the lower path
   (`0x44[0]`), CSID2 would work and anything through the upper field (CSID3) would get no lane events.
   This matches every result so far.
2. **The front→CSID3 control may use a route Windows never uses.** In this table CSID3 maps only to
   field 15, the PHY2 *upper* field. The front control set PHY2 *lower* field = 3. A zero-event result
   there does not by itself show CSID3 is broken.

**Read-only check first:** read `0xfda00040` and `0xfda00044` (and `0x34/0x3c` for comparison) on the
installed kernel with the front camera streaming on CSID2, and again during the iris one-shot. Expect
`0x44[0] = 1` if the select-bit model is right. Only after that, consider a one-shot that also sets
`0x44[1] = 1` before stream-on (and restores it at cleanup). The exact meaning of the `0x44` bits
("cgc" suggests clock gating) is inferred from the driver structure, not from documentation.

### ACPI

DSDT `CAMT` (`QCOM2436`, the iris sensor) has only `0xFDA08C00` (CSID3) and IRQ `0x56`. No PHY or settle
data lives in ACPI. `CAMP` (`QCOM245E`) owns CCI `0xFDA0C000` and CAMSS TOP `0xFDA00000` plus GPIOs.

## 4. Iris vs front sensor driver

Same SMIApp code. After normalizing addresses, 171 of 171 string-matched functions are identical.
The remaining differences are naming, the allowed CSID range (iris accepts 1..3, front 1..2) and
source line numbers. **The Windows code has no iris-only startup step.** Behaviour differences come from
data (DCC/NVM/ACPI), which keeps sections 2 and 3 the relevant comparisons.

`SensorDeviceActivate` in both drivers also contains a config-gated PMIC path ("PmicLpgTurnRGBLedON",
SPMI `0xD045 = 1`, `0xD046 |= 0x20`). Its purpose on this device is not established here. Keep it out of
any test until it is understood.

## 5. IR illuminator (`qccamflashtertiary8994.sys`), for later

- Driven through the PMIC flash LED path (`IOCTL_PM_FLASHLED_INIT_PARAM`, `pmic_flash_power_on`, watchdog
  petting, thermal derating fault, vph_pwr droop logging). Per-device config is loaded from
  `\Registry\Machine\Software\OEM\MMO\Camera\TFF`.
- `tff_ir1_assist_current_cfg` (`0x403b8c`) accepts only power levels 13, 20, 30 and 100 (%), mapped to
  current codes `10, 15, 23, 22` for LED ID 7 (as decompiled; units not established).
- Pulse validation (`0x407b14`): power > 100 is rejected. Modes 1/2 clamp pulse length to 80000 and
  mode 3 to 40000 (likely µs), with a 1000 lower branch.
- Per-LED request < 25 and total < 49 (`0x408aac`, units unknown). A heat-load cooldown engages above
  2000 ms of accumulated load (`0x404430`).

Treat these as the original driver's guard rails when IR work starts. They are not validated
eye-safety limits.

## 6. Capture/authentication layer (`CameraAuthentication.dll`)

This is a frame provider, not a matcher. It runs exposure control from eye ROI statistics
(`EyeROI[n]`, `EyeStatsAecControl.p90Target/...`, `IrisPct_*`), and it syncs an IR pulse per frame
(`FlashCtrlPulseUs`, `IS.HE.FlashPulseLenghtUs`, `UseFlashOutOfFrame`). Defaults are read from camera
init parameters, not hard-coded. It matters only after frames arrive.

## 7. Not done here

- The DDR clock value for the iris mode was not extracted, so the settle number above is a formula,
  not a final value.
- PHY status bit names are still not recovered. The ISP driver (`qccamisp8994.sys`, decompiled: 632
  functions) was not analysed in depth.
- Nothing was run on a phone.

Reproduce:

```sh
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC rea decompile-all /abs/path/qccamsensor_tertiarySMIApp8994.sys \
  --output /abs/path/pseudo --provider ghidra
```
