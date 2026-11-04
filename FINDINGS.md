# Findings: Ghidra/REA pass over the original Windows camera drivers

Target: `qccamsensor_tertiarySMIApp8994.sys` from WOA-Project/Lumia-Drivers @ `b5af93f9`,
SHA-256 `0ea99897a1623afd7f165aa2943f2f69687c31dc42a123d6d21c2339ca8e78e5` (same file as `docs/hardware.md`).
Tooling: REA 6.8.0 `decompile-all` with Ghidra 12.1.4 (ARM Thumb, PE). 363 functions decompiled.
Everything below is static decompiler output, not observed execution. Function names come from the
driver's own trace strings.

**Update after commit `3cb4fad`:** the owner's phone tests ruled out the `0x44` lead (the register already
reads `0x03`), the settle values, VC0, CSI-2 selection, the reset delay and NVM config entries. The new
lead is in section 11: **Windows enables `camss_csi3phy_clk` for the iris, and in the recorded Linux runs
that clock was disabled.** That would explain both the iris result and the front-camera-on-CSID3
control. The text below this paragraph is kept as it was written.

**Update after commit `e7e62a3` (front camera gets zero lane IRQs on CSID3):** the strongest lead is now
the **CAMSS TOP select register `0xFDA00044`**, which Windows writes and the Linux kernel never touches
(section 3, "Clock mux"). Suggested order:
(1) read `0xfda00040/0xfda00044` read-only on a working CSID2 stream and during the iris one-shot;
(2) if `0x44[1]` is 0, a one-shot that sets it before stream-on;
(3) read the sensor OTP for `'!'` NVM config entries (section 2);
(4) optionally compare settle `0x16`–`0x18` (Windows / mainline, sections 7 and 9) with `0x14`.
The PHY status already latched bit 2 on exactly the two iris lanes (3 and 4) while CSID3 saw nothing,
which points at the PHY-to-CSID link (section 9). Reading the same words on a working CSID2 stream
is a cheap control.
The kernel #9 readback `0x0308 = 0` is probably harmless: for model `0x0861` the original driver
does not use `0x0308` at all (section 7).
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

## 7. Model `0x0861` clock tree: `0x0308` is not used (`cam_drv_SMIApp_compute_output_modes`, `0x411f9c`)

LumiaFaceID kernel #9 read back `0x0308 = 0x0000` although the mode program writes `0x0008`.
The original driver computes clocks for this exact sensor with a **model-specific formula**. For
manufacturer `0x0c` / model `0x0861` (checked at `0x411f9c`, lines testing `+0x16d == 0x0c` and
`+0x164 == 0x861`):

```c
// generic SMIA++ sensors
vt_pix_khz = ext * pll_mult / (pre_pll_div * vt_sys_div * vt_pix_div);
op_pix_khz = ext * pll_mult / (pre_pll_div * op_sys_div * op_pix_div);
// model 0x0861
vt_pix_khz = ext * pll_mult / ((pre_pll_div + 1) * vt_sys_div);
op_pix_khz = ext * pll_mult / ((pre_pll_div + 1) * op_sys_div);
```

Here `pre_pll_div = 0x0304`, `pll_mult = 0x0306`, `vt_sys_div = 0x0302`, `vt_pix_div = 0x0300`,
`op_sys_div = 0x030a` and `op_pix_div = 0x0308`. For `0x0861` the driver ignores both `vt_pix_div` and
**`op_pix_div` (`0x0308`)**, and treats the pre-divider as "value + 1". The driver still requires
`op_pix_div` to be nonzero in the *mode program* (it rejects `op_sys_div * op_pix_div == 0`), but
that check runs on the DCC values, not on a readback. Two reads follow from this, neither verified:
`0x0308` may not be a real register on this sensor, or it may be write-ignored. Either way,
**`0x0308 = 0` on readback is probably not a fault**, and it should not drive the next test.

With the mode values from LumiaFaceID's `IRIS-PLL.md` (`pre = 1`, `mult = 0x92 = 146`, `vt_sys = 10`,
`op_sys = 1`) and EXTCLK `0x099a` = 9.6 MHz (`ext x100 = 960`):

| Quantity | Value |
| --- | --- |
| VT pixel clock | 9.6 × 146 / (2 × 10) ≈ **70.08 MHz** |
| OP pixel clock | 9.6 × 146 / (2 × 1) / 10 ≈ **70.08 MHz** (the `× 10` is in the driver's `op` divisor) |
| 1-lane RAW10 bit rate | ≈ 700.8 Mbit/s |
| DDR clock (bit rate / 2) | ≈ 350.4 MHz |
| Windows settle at 200 MHz timer | `((4e9 / 350.4e6) + 100) × 0.2 + 0.5` → **22 = `0x16`** |

The diagnostic uses `0x14`. A difference of 2 ticks (10 ns) is small. Settle is therefore an unlikely
root cause, but `0x16` is the Windows-equivalent value if it is ever compared. Assumptions to check:
the driver's `ext` input (`DAT_0083b380`) equals the EXTCLK value, and the KMD's `MIPIDDRClock`
equals bit rate / 2. `ConfigResolution` computes data rate as `ddr / 1000 × lanes × 2`, which supports
the second point.

## 8. Does firmware already set `0xFDA00044`?

Unknown. A code search of the WOA-Project GitHub organisation (UEFI, ACPI, driver definitions) finds
no reference to `FDA00040`, `FDA00044` or `0xFDA00000`. The original Lumia boot firmware is closed.
Only a register read on the phone can answer this.

## 9. PHY status words: layout, and why the existing readback matters

Bit names for the 2-phase CSIPHY interrupt status are not public. The Windows drivers contain no
decode strings (the iris driver only copies PHY `+0x18c..+0x1a8` into a diagnostic snapshot at
`0x41ee68`), and Qualcomm's register descriptions require a login. The layout is available from
mainline Linux [`camss-csiphy-2ph-1-0.c`](https://github.com/torvalds/linux/blob/master/drivers/media/platform/qcom/camss/camss-csiphy-2ph-1-0.c),
which uses the same offsets as MSM8994 (`GLBL_RESET 0x140`, `GLBL_PWR_CFG 0x144`,
`INTERRUPT_STATUSn 0x18c + 4n`, `MASKn 0x1ac + 4n`, `CLEARn 0x1cc + 4n`). Its lane setup writes
`MASK(l) = CLEAR(l) = 0x3f` **for each enabled lane `l`**, so the per-lane status word index equals the
lane position, with 6 event bits per lane.

LumiaFaceID's kernels #7 and #8 recorded **status words 3 and 4 = `0x4`** and word 6 = `0x10`, while words
0–2 stayed 0. The iris uses combo lane mask `0x18`: **lane 3 is the clock and lane 4 the data lane.**
So the same bit (bit 2) was latched on exactly the two iris lanes and on no other lane. The bit's
name is still unknown. But if word `n` is lane `n`, then the PHY observed *some* lane-level event on
the iris lanes while CSID3 counted nothing. That is the signature of a break **between PHY and CSID**,
which is exactly where the CAMSS TOP mux/select registers (section 3) sit.

**Cheap control:** read the same eight words during the working front stream on CSID2 (lanes 0–2).
If bit 2 also appears on the front's lanes there, it is a normal lane-activity indicator, and the
iris result means the sensor does drive its lanes. If it does not, bit 2 is more likely an error or
idle-state flag. Remember that the owning IRQ handler clears these words, so a zero is not proof of
inactivity.

### Settle: three sources

At the computed link (DDR) clock of ≈ 350.4 MHz (section 7) and a 200 MHz PHY timer:

| Source | Formula | Value |
| --- | --- | --- |
| LumiaFaceID diagnostic | fixed | `0x14` |
| Original Windows driver | `(4e9/ddr + 100 ns) × timer + 0.5` | `0x16` |
| Mainline Linux 2ph | `((85 + 6·UI) + (145 + 10·UI)) / 2` ns ÷ timer period − 1 | `0x18` |

(UI ≈ 1.43 ns at 700.8 Mbit/s.) The diagnostic is the lowest of the three. A too-short settle usually
causes SoT/ECC errors rather than silence, so this stays secondary to section 3. If settle is ever
compared, `0x16`–`0x18` is the supported range.

## 10. Not covered again here

- Windows CSIPHY/CSID programming in the iris driver (`0x83d220` maps PHY2 at `0xfda0b400`; lane
  construction, `CORE_CTRL_1` bit 16, statistics readers) is already analysed in LumiaFaceID's
  `docs/iris-csi.md`. This pass found nothing that contradicts it. The one receiver-side item missing
  there is the CAMSS TOP select register in section 3.
- `qccamisp8994.sys` handles only VFE/CPP (image processing). It contains no CSID or CSIPHY setup.
- PHY status bit names are still not recovered (section 9 gives the layout only).
- Nothing was run on a phone.

## 11. `camss_csi3phy_clk`: Windows enables it for the iris, Linux leaves it off

**Phone results this responds to (LumiaFaceID `3cb4fad`):** `0xfda00044` was already `0x03` and
`0x40` became `0x30` during the iris run, so the section 3 select bit was set. Settle `0x16`, 1–63, VC0,
`0x0111=2`, the 10 ms reset wait and an NVM header without config entries all left the sensor frame
counter and CSID3 packets at zero. The front-camera PHY status during preview was words 0–5 and 7 = 0,
word 6 = `0x1`. CSID3's internal test generator does count packets, so CSID3 itself works.

**Source:** the ACPI power resources in the Lumia DSDT
([WOA-Project/Lumia950XLPkg `DSDT.asl`](https://github.com/WOA-Project/Lumia950XLPkg/blob/cfc68a4d19fc7e8645bff6d8fce7308ad8494a76/AcpiTables/8994/src/DSDT.asl)).
In each camera device's D0 sequence, the CSI clocks it enables are:

| ACPI device | Sensor route | CSI clocks in D0 |
| --- | --- | --- |
| `CAMS` (rear) | PHY0 → CSID0 | `camss_csi0_clk`, **`camss_csi0phy_clk`**, `camss_mclk0_clk` |
| `CAMF` (front) | PHY2 lower → CSID2 | `camss_csi0_clk`, `camss_csi2_clk`, **`camss_csi2phy_clk`**, `camss_mclk2_clk` |
| `CAMT` (iris) | PHY2 upper → CSID3 | `camss_csi0_clk`, `camss_csi2_clk`, `camss_csi3_clk`, **`camss_csi3phy_clk`**, `camss_mclk1_clk` |

The `csiNphy` clock follows the **CSID** number, not the PHY number. The iris uses PHY2, but Windows
enables `csi3phy`, not `csi2phy`. MSM8994 has three PHYs and four `csiNphy` clocks, which also fits
per-CSID clocks. Mainline Linux agrees: its CSID resources list `csiN_phy` as a CSID clock
(`camss.c`, `csid_res_8x96`: `"csi0", "csi0_phy", "csi0_pix", "csi0_rdi"`).

The pinned downstream DT does it differently. Each `qcom,csiphy` node carries the clock with its own
index (PHY2 → `clk_camss_csi2phy_clk`), and the `qcom,csid@fda08c00` node has no `csi3phy` clock at all.
So Linux enables `csi2phy` whenever PHY2 is used, whichever CSID the CAMSS TOP mux selects. LumiaFaceID's
`kernel/IRIS-CSID3-CONTROL.md` ("Clock state during a repeated front-camera control") recorded exactly
this: `camss_csi2phy_clk` enabled, **`camss_csi3phy_clk` disabled**.

**Interpretation (not verified):** setting the TOP mux to 3 points PHY2 at CSID3's PHY-interface clock.
If that clock is gated, the PHY can still see lane activity (bit 2 on lanes 3/4, section 9), but nothing
reaches CSID3. That fits all three observations: the iris gets zero packets, the front sensor also gets
zero when routed to CSID3, and the internal test generator works because it bypasses the PHY interface.
The normal front route matches the Windows pattern (CSID2 with `csi2phy` on), and it works.

**Confirmed in the pinned kernel** (`giannoccarol/android_kernel_mmo_msm8994` @ `cc84cab9`):

- `drivers/clk/qcom/clock-mmss-8994.c`: `camss_csi3phy_clk` (CBCR `0x31F4`) has parent
  `csi3_clk_src`, and `camss_csi2phy_clk` (CBCR `0x3194`) has parent `csi2_clk_src`. So each `csiNphy`
  branch is generated from CSID N's clock source.
- `msm_csiphy.c` writes `csid_core` into the `csiphy_clk_mux` field (`<< 4` for combo upper lanes). The
  mux picks which CSID's `csiNphy` clock drives the PHY. It does not enable that clock.
- The PHY2 node only lists `clk_camss_csi2phy_clk` as `csi_phy_clk`, and the CSID3 node has no PHY
  clock. Nothing in the tree enables `camss_csi3phy_clk`.

A minimal DT change for a test build (CSID3 node `qcom,csid@fda08c00`, append as the 9th entry; the
limit is `CSID_NUM_CLK_MAX = 16`, and `msm_csid` enables every listed clock in order):

```dts
clocks = <... existing 8 ...>, <&clock_mmss clk_camss_csi3phy_clk>;
clock-names = <... existing 8 ...>, "csi_phy_clk";
qcom,clock-rates = <0 0 240000000 0 0 0 0 0 0>;
```

Rate 0 means the driver does not set a rate, so the branch runs at its parent's 240 MHz. One caveat:
`csid_clk_info[]` in `msm_csid.c` is a static array shared by all CSID instances. If another CSID probes
after CSID3, its 8 entries overwrite the first 8 slots. Slot 9 keeps rate 0, which is harmless here.
Doing the enable in the iris driver instead (`clk_get` + `clk_prepare_enable` around the run) avoids
touching the shared camera stack.

**Suggested one-shot:** keep everything as in the current `csi-trial 22` run, and additionally
`clk_prepare_enable` `camss_csi3phy_clk` (its parent `csi3_clk_src` is already enabled at 240 MHz in the
recorded runs) before PHY2 is configured. Disable it after the receiver is released. Read back with
debugfs that it is enabled during the run. An even cheaper first check is the front camera routed to
CSID3 with `csi3phy` enabled, since that sensor is known to transmit.

**Secondary:** `CAMT` also enables `camss_csi2_clk` and `camss_csi0_clk`, which the iris path does not
use directly. They may be ordering or shared-resource votes. Try them only if `csi3phy` alone does not
change the packet count.

**Also in the same DSDT:** `BOOST_BYPASS1_B` (4.0 V) is the first vote in `CAMT` D0 and the
last one released in D3, so it brackets the sensor rails. No other camera or flash device votes it
(the only other user is audio). Its role is still unproven, so it stays after the clock test.

## 12. The sensor's own frame counter: a second, sensor-side problem

Section 11 can explain why CSID3 counts nothing. It **cannot** explain why the sensor's frame counter
(`0x0005`) stays at `0x00`. That counter is inside the sensor, and MIPI CSI-2 has no back channel, so
a gated clock on the SoC side does not stop the sensor from counting frames.

The original driver confirms what the register means. `cam_drv_SMIApp_pause` (`0x411a4c`) reads
`0x0005` and logs it as "Last frame count". During its slow stop it polls `0x0005` and treats `0xFF` as
"streaming stopped". So `0x0005` really is the frame counter here, and `0xFF` is its idle value.

The expected rate is easy to compute from the readbacks. Frame length is `0x045c` = 1116 lines, line
length is `0x0834` = 2100, and the pixel clock is 70.08 MHz (section 7). That gives 33.4 ms per frame.
The diagnostic samples 16 × 20 ms = 320 ms, which is about 9 frames, but it saw 0 changes.

Two readings:

- `0x0005` was `0xFF` before stream-on and became `0x00` after. Then the sensor did enter streaming
  (`0x0100` also reads back 1), but it never finished a frame. That points at the analog/PLL side of
  the sensor, not at the receiver.
- `0x0005` was already `0x00` before stream-on. Then the counter says nothing either way.

The current snapshot only samples `0x0005` after `0x0100=1`. (The `0xff` in `stream_before` of
`iris-csi-03` has `samples: 0`, so it looks like an initial value, not a read.) **One extra read of
`0x0005` just before `0x0100=1` would separate the two cases.**

If it is the first case, the remaining power difference from Windows is `BOOST_BYPASS1_B` (section 11):
Windows votes it first in `CAMT` D0 and releases it last in D3, bracketing the sensor rails. The PLL
values are not a suspect, since Windows writes the same DCC values.

Checked and **not** a difference:

- EXTCLK: Windows `cam_drv_SMIApp_on` (`0x40bf24`), Siiri branch, writes `0x0103=1`, waits 10 ms, and
  writes `0x0136 = (ext×256+50)/100`, which is the same as Linux. `0x0130=0x099a` comes from the DCC mode
  program on both sides. In the generic branch, the driver logs `0x0130/0x0132/0x0134` as supply
  voltage hints ("Setting Vana voltage"), but the Siiri branch does not write them.
- MCLK1 pin: the iris DT node selects `cam_sensor_mclk1_active` (GPIO14), the same pin as `CAMT`
  (`TLMMGPIO 0x0E`, function 1).
- GPIO106: in the DSDT it only appears in another device's (`SDFR`) GPIO list, not in `CAMT`.

**Suggested order:**

1. Front camera on CSID3 with `camss_csi3phy_clk` enabled. This tests section 11 alone, because that
   sensor is known to transmit.
2. Iris with `csi3phy`, plus one `0x0005` read before stream-on.
3. If the counter goes `0xFF → 0x00` and stays there, then try a bounded one-shot with
   `BOOST_BYPASS1_B`, following the `CAMT` order.

## 13. Result of section 11, and the next lead: regulator load (LDO HPM vs LPM)

**Phone result (LumiaFaceID `3ea51c1`):** with `camss_csi3phy_clk` added to the CSID3 clock list, the
working front camera routed to CSID3 delivered **416 frames**. CSID3 counted 1,094,240 packets with no
ECC/CRC errors. Earlier, without that gate, the same control produced zero. The receiver-side gap from
section 11 is therefore real and closed. The iris on the same boot still produced zero packets. Its
`0x0005` already read `0x00` before stream-on and never changed. `csi2_clk`/`csi0_clk` votes changed
nothing. That leaves the sensor side (section 12).

**New lead: the iris driver never sets a regulator load.** The Windows `CAMT` D0 votes include a
current for each sensor rail (DSDT `PMICVREGVOTE`, voltage in µV then current in µA):

| Rail | Windows voltage | Windows current | LumiaFaceID iris driver |
| --- | --- | --- | --- |
| `LDO17_A` (vana) | 2.8 V | **300 mA** (`0x493E0`) | `regulator_enable` only, no load |
| `LVS1_A` (vio) | 1.8 V | 300 mA | switch, no mode |
| `SMPS3_A` (core) | 1.3 V | 300 mA | no load |
| `LDO3_A` (vdig) | 1.2 V | **80 mA** (`0x13880`) | no load |

In the pinned kernel (`arch/arm/boot/dts/qcom/msm-pm8994-rpm-regulator.dtsi`), `rpm-regulator-ldoa17`
and `ldoa3` have `qcom,hpm-min-load = <10000>`, and `smpa3` has `<100000>`. The RPM-SMD regulator only
asks for high-power mode when the summed consumer load reaches that threshold. A consumer that only
calls `regulator_enable()` adds 0 µA, so the LDO stays in low-power mode (LPM). That mode is meant for
a few mA.

The Linux front camera shows this rail needs HPM. `cityman.dtsi` gives the front sensor
`cam_vana-supply = <&pm8994_l17>` with `qcom,cam-vreg-op-mode = <300000 0>`, and `msm_camera_config_vreg`
applies it with `regulator_set_optimum_mode()`. During the iris trials the camera services are
stopped, so no other client is holding L17 in HPM.

**Why this fits the symptoms:** in LPM a sensor can still answer CCI and accept register writes, which
all draw very little current, and the voltage reads correctly at no load. When it starts streaming,
the pixel array, ADCs and PLL draw tens of mA. On an LDO in LPM, that can make the analog part fail,
and the sensor never finishes a frame. This matches what was seen: model ID OK, every readback OK,
`0x0100` reads 1, but `0x0005` stays at `0x00`.

**Cheap read-only check:** during an iris trial, with camera services stopped, read
`/sys/kernel/debug/regulator/pm8994_l17/` (`mode`, `optimum_mode` or the consumer load list, whichever
this 3.10 tree provides). Do the same for `pm8994_l3`. In Linux, `REGULATOR_MODE_NORMAL` = 2 (HPM) and
`IDLE` = 4 (LPM).

**Suggested change** (iris driver, around the existing `regulator_enable()` / `regulator_disable()`):

```c
static const int rail_load_ua[IRIS_RAILS] = { 300000, 0, 300000, 80000 }; /* CAMT D0 votes */

/* before regulator_enable(iris->rails[i]) */
if (rail_load_ua[i])
	regulator_set_optimum_mode(iris->rails[i], rail_load_ua[i]);

/* after regulator_disable(iris->rails[i]) */
if (rail_load_ua[i])
	regulator_set_optimum_mode(iris->rails[i], 0);
```

The order matches `rail_names` (vana, vio, core, vdig). `regulator_set_optimum_mode()` returns the
selected mode or a negative error, so it is worth logging. This only changes the regulator's power
mode. Voltages stay the same, and it is what the Linux front camera already does on L17.

If this does not change `0x0005`, `BOOST_BYPASS1_B` remains the last power difference from `CAMT`.

**Checked in the pinned regulator driver** (`drivers/regulator/rpm-smd-regulator.c` @ `cc84cab9`): the
LDO mode follows the requested current. `rpm_vreg_get_optimum_mode()` stores the consumer load as the
RPM `CURRENT` request and returns `NORMAL` only when `load_uA + system_load >= hpm_min_load`.
`rpm_vreg_get_mode()` uses the same comparison. Neither `pm8994_l17` nor `pm8994_l3` sets
`qcom,init-current` or `qcom,system-load` in the pinned DTs. So without a `regulator_set_optimum_mode()`
call, the applications processor's current request for both LDOs is 0 mA, which is LPM. The RPM still
aggregates requests from other processors, which is why the debugfs read during a trial is the
deciding check.

### 13a. More detail from the same DSDT votes

The 10-element LDO votes match Qualcomm's `PMICVREGVOTE` layout: name, type (1 = LDO), µV, µA,
software enable, pin-control enable, **software power mode**, pin-control power mode, bypass,
headroom. For `LDO17_A` and `LDO3_A`, the power-mode field is **1 in both the D0 and D3 votes**. In
Qualcomm's LDO mode enum, 0 is current-based (IPEAK) and 1 is forced NPM (normal/high power). If that
enum applies here, Windows does not only send a current, it also pins both LDOs to NPM. The enum
values are from memory of Qualcomm's PMIC NPA interface, not from this DSDT, so treat this as
supporting evidence.

The front camera (`CAMF`) votes only `LDO17_A` and `LVS1_A`, with the same 2.8 V / 300 mA / mode 1 on
L17. The iris additionally needs `SMPS3_A` (1.3 V) and **`LDO3_A` (1.2 V, 80 mA)**. So L3 is used only
by the iris, and no working camera on Linux has ever run with L3 in HPM. The LumiaFaceID result line
`rail_uv=1200000` is this L3 rail. Its voltage reads correctly, but that says nothing about its
mode.

Windows power-on order and delays (`DELAY` units as written in the DSDT): boost → 1 → L17 → 1 → LVS1 →
1 → S3 → 1 → L3 → 1 → clocks including MCLK1 → GPIO14 (MCLK function) → 1 → GPIO102 (reset) high → 3.
Power-off is the reverse, with 5 after the clocks and 10 after L17. The rail order matches
LumiaFaceID's `rail_names`.

### 13b. Upper-combo PHY configuration: no new difference

The `iris-csi3phy-precount-01` readback shows the downstream combo setup as intended. PHY power is
`0x31` (lane mask `0x18`), mode is `0x10` (combo), the lane 3 (clock) MISC1 is `0x4`, and the lane 4
(data) MISC1 is `0x8`. This matches `msm_csiphy.c` for `qcom,csiphy-v3.1.1` (`is_3_1_20nm_hw`): "in
combo mode the clock is always the 4th lane". Settle is `0x16` on both. The front control on CSID3
proved the lower lanes only, but the upper configuration that Linux writes is what the driver
intends.

The eight PHY status words are all 0 **before** stream-on and only become `0x4` on words 3 and 4 (the
iris lanes) plus `0x10` on word 6 **after** it. A working front stream leaves its lane words at 0. So
something does happen on exactly the iris lanes when the sensor is told to stream, but it is not
what a healthy link produces. A sensor whose TX starts but cannot keep running, for example because
its supply is weak, would fit that.

### 13c. Caveat on `0x0005`

The iris reads `0x0005 = 0x00` **before** stream-on. The original driver's stop loop treats `0xFF`
as the idle value (section 12). So this sensor's counter may not behave like the standard one, and
"counter stays 0" is weaker evidence than it first looked. A cheap check: read `0x0005` once more
after the sensor stop (`0x0100=0` plus one frame time). If it never shows `0xFF` on this sensor, do
not rely on it, and use CSID3 packets as the only success criterion.

## 14. Combo upper lanes: Windows sets bit 1 in lane MISC1, Linux does not

**Phone result this responds to (LumiaFaceID `ac6db19`):** the baseline really had L17, L3 and S3 in
LPM (`mode=4`). With the load votes, all three reached HPM (`mode=2`), but CSID3 still counted zero
packets. `0x0005` read `0x00` before stream-on and 40 ms after stop, so it is not a usable indicator
(section 13c). Power mode is real but not sufficient.

That leaves the path the front-camera control did not cover: **PHY2's upper combo lanes 3/4**.

**Windows PHY programming.** The iris driver programs PHY2 directly in `0x41e914` (full init,
reached from `0x41d928` with `param_2 == 1`). The per-lane `MISC1` value (PHY offset `0x28 + 0x40·n`)
comes from `0x41dbb4(lane, combo)`. I checked that function in the disassembly as well, not only in
the decompiler output. It builds `16·a + 8·b + 4·c + 2·d + e`:

| Lane | Windows, non-combo | Linux, non-combo (4-lane) | **Windows, combo** | **Linux, combo (mask `0x18`)** |
| --- | --- | --- | --- | --- |
| 0 | `0x00` | `0x00` | `0x00` | not written |
| 1 | `0x04` | `0x04` | `0x04` | not written |
| 2 | `0x28` | `0x28` | `0x08` | not written |
| 3 | `0x18` | `0x18` | **`0x06`** | **`0x04`** (readback `phy_clock_misc`) |
| 4 | `0x08` | `0x08` | **`0x0A`** | **`0x08`** (readback `phy_data_misc`) |

The Linux values are from `msm_csiphy_lane_config()` (`is_3_1_20nm_hw` path). In non-combo mode
Linux and Windows agree on every lane, which shows the field mapping is right. **In combo mode
Windows additionally sets bit 1 (`0x2`) on exactly the two upper lanes.** Linux never produces that
bit: its combo branch only forces `0x4` on the first upper lane.

**Interpretation (not verified):** bit 1 appears only on upper-combo lanes, so it most likely tells
the lane that it belongs to the second (upper) receiver group with its own clock on lane 3. Without
it, data lane 4 may still be tied to the lower clock lane 1, which is idle when only the iris runs.
That would fit every result so far: the lower path works on CSID3 (416 frames), the upper path never
delivers a packet, and the PHY latches status bits on exactly lanes 3/4 after stream-on.

**Other per-lane differences** (same function, written for all five lanes in Windows; Linux values
are what the front/rear cameras already use successfully):

| PHY lane register | Windows | Linux |
| --- | --- | --- |
| `CFG1` (`+0x00`) | `0x00` | not written |
| `CFG2` (`+0x04`) | `0x3f` | `0x10` |
| `CFG3` (`+0x08`) | settle | settle |
| `CFG4` (`+0x0c`) | `0xff` | not written |
| `CFG5` (`+0x10`) | `0x22` | not written |
| `TEST_IMP` (`+0x1c`) | `0x17` | `0x17` |
| `GLBL_RESET` | `0x11` then `0x10` (combo) | `0x10` |
| `GLBL_PWR_CFG` | lane bits \| 1 (= `0x31` for iris alone) | `0x31` |

**Suggested one-shot:** keep the current `csi-trial 22` setup (with the `csi3phy` vote), and after
`msm_csiphy_lane_config()` returns, before sensor stream-on, write PHY2 `MISC1` lane 3 = `0x06` and
lane 4 = `0x0A` (offsets `0x28 + 0x40·3 = 0xE8` and `0x28 + 0x40·4 = 0x128`). Read them back. Success
is CSID3 packets > 0. Only if that alone does nothing, a second variant can also apply the Windows
`CFG1/2/4/5` values to lanes 3/4.

## 15. Not covered again here (update)

Section 10 still applies. Sections 11–14 are static ACPI/DT/driver analysis. The results quoted at
the start of sections 13 and 14 come from LumiaFaceID's own phone tests.

Reproduce:

```sh
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC rea decompile-all /abs/path/qccamsensor_tertiarySMIApp8994.sys \
  --output /abs/path/pseudo --provider ghidra
```
