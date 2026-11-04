/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * EXPERIMENTAL, NOT TESTED ON HARDWARE - Lumia 950 XL (cityman) iris camera,
 * SMIA model 0x0861 (manufacturer 0x0c, "Siiri" in the Windows driver).
 *
 * Built against the angler plug-in interface of
 * giannoccarol/android_device_msft_cityman (lineage-23-cityman),
 * camera-sensors/imx230/angler_sensor_abi.h. The structure follows that
 * tree's camera-sensors/vs6955/sensor_lib_vs6955.c (front camera).
 *
 * Wiring from the Lumia ACPI DSDT (CAMT / QCOM2436) and LumiaFaceID's
 * phone tests:
 *   CCI master 0, 8-bit slave 0x6c (7-bit 0x36), 16-bit register address
 *   CSIPHY2 upper combo lanes (clock 3, data 4) -> CSID3, MCLK1 9.6 MHz
 *   reset GPIO 102 (no standby GPIO)
 *   VANA L17 2.8 V, VIO LVS1 1.8 V, core S3 1.3 V (cam_v_custom1),
 *   VDIG L3 1.2 V. Windows load votes: 300 / - / 300 / 80 mA.
 *
 * Receiving packets on CSID3 also needs the kernel changes in
 * ../../kernel/: camss_csi3phy_clk on CSID3, and MISC1 bit 1 on the upper
 * combo lanes. Without them the CSID counts zero packets.
 *
 * The original driver reads gain, pedestal and pixel order from the sensor at
 * start-up instead of hard-coding them (cam_drv_SMIApp at 0x40f374 and
 * 0x4107f8). The IR0861_SENSOR_* values below must be filled from one
 * read-only dump of those registers on the phone. The defaults reproduce a
 * common SMIA gain model and are placeholders. Mount angle, lens data and
 * tuning are also still placeholders.
 *
 * The register program comes from the stock Lumia DCC (same bytes as
 * LumiaFaceID's private cityman-iris-stream-profile.hex). It must not be
 * committed to a public tree; generate-ir0861.py writes it to the build dir.
 */
#include "angler_sensor_abi.h"
#include "ir0861_registers.generated.h"

#define SETTING(a, type, wait) { .reg_setting = (a), .size = COUNT(a), \
    .addr_type = MSM_CAMERA_I2C_WORD_ADDR, .data_type = (type), .delay = (wait) }
#define POWER(type, value, config, wait) { .seq_type = (type), .seq_val = (value), \
    .config_val = (config), .delay = (wait) }

/* Windows Siiri startup: software reset, 10 ms, EXTCLK 9.6 MHz (0x099a). */
static struct msm_camera_i2c_reg_array reset[]  = {{0x0103, 1, 0}};
static struct msm_camera_i2c_reg_array extclk[] = {{0x0136, 0x09, 0}, {0x0137, 0x9a, 0}};

static struct msm_camera_i2c_reg_array stream_on[] = {
    /* The DCC has no frame length or exposure: seed both before streaming. */
    {0x0104, 1, 0},
    {0x0340, 0x04, 0}, {0x0341, 0x5c, 0},   /* 1116 lines, 29.9 fps */
    /*
     * 1000 lines, about 30 ms. LumiaFaceID's diagnostic used 12 lines
     * (0.36 ms), which only works with a strong IR pulse per frame.
     */
    {0x0202, 0x03, 0}, {0x0203, 0xe8, 0},
    {0x0204, 0x00, 0}, {0x0205, 0x38, 0},   /* gain code 56, as in the diagnostic */
    {0x0104, 0, 0},
    {0x0111, 2, 0},   /* CSI-2 signalling, as the Windows sensor_config path */
    {0x0110, 0, 0},   /* virtual channel 0 */
    {0x0100, 1, 0},
    {0x0138, 1, 0},   /* Windows unpause writes this after mode select */
};
static struct msm_camera_i2c_reg_array stream_off[] = {
    {0x0138, 0, 0},
    {0x0100, 0, 0},
};
static struct msm_camera_i2c_reg_array hold_on[]  = {{0x0104, 1, 0}};
static struct msm_camera_i2c_reg_array hold_off[] = {{0x0104, 0, 0}};

/*
 * Mode 0 of the matched DCC: 1920x1088 RAW10, one lane, line length 2100.
 * Clocks from the Windows PLL formula for this model with 0x0304=1,
 * 0x0306=0x92, 0x0302=10: 9.6 MHz * 146 / (2 * 10) = 70.08 MHz pixel clock,
 * 700.8 Mbit/s on the single lane.
 */
#define IR0861_LINE_LENGTH  2100u
#define IR0861_FRAME_LINES  1116u
#define IR0861_MCLK         9600000u
#define IR0861_VT_CLOCK     70080000u
#define IR0861_OUTPUT_CLOCK 70080000u
#define IR0861_MAX_FPS      29.9f
/*
 * Fill from the phone (all read-only, 16-bit big-endian unless noted):
 *   0x0084/0x0086/0x0088  analogue gain code min / max / step
 *   0x008c/0x008e/0x0090/0x0092  m0 / c0 / m1 / c1 (signed)
 *   0x1006                coarse integration time max margin
 *   0x0008                data pedestal (black level, 10-bit units)
 *   0x0006 (8-bit, with 0x0101 = 0)  pixel order, CCS: 0 GRBG, 1 RGGB, 2 BGGR, 3 GBRG
 * The original driver uses gain = (m0 * code + c0) / (m1 * code + c1), the
 * SMIA analogue gain model, with only a 0x022e-specific tweak (not this model).
 */
#define IR0861_SENSOR_GAIN_CODE_MIN   0
#define IR0861_SENSOR_GAIN_CODE_MAX   448
#define IR0861_SENSOR_GAIN_CODE_STEP  1
#define IR0861_SENSOR_GAIN_M0         0
#define IR0861_SENSOR_GAIN_C0         512
#define IR0861_SENSOR_GAIN_M1         (-1)
#define IR0861_SENSOR_GAIN_C1         512
#define IR0861_SENSOR_COARSE_MARGIN   8u
#define IR0861_SENSOR_PEDESTAL        64
#define IR0861_SENSOR_PIXEL_ORDER_CCS 2   /* BGGR; a monochrome die still reports one */

/* CCS pixel order -> angler Bayer enum (0 BGGR, 1 GBRG, 2 GRBG, 3 RGGB). */
#define IR0861_BAYER_ORDER (IR0861_SENSOR_PIXEL_ORDER_CCS == 0 ? 2u : \
                            IR0861_SENSOR_PIXEL_ORDER_CCS == 1 ? 3u : \
                            IR0861_SENSOR_PIXEL_ORDER_CCS == 2 ? 0u : 1u)
#define IR0861_MAX_LINES    (65535u - IR0861_SENSOR_COARSE_MARGIN)

static float ir0861_gain_from_code(uint32_t code)
{
    return ((float)IR0861_SENSOR_GAIN_M0 * (float)code + (float)IR0861_SENSOR_GAIN_C0) /
           ((float)IR0861_SENSOR_GAIN_M1 * (float)code + (float)IR0861_SENSOR_GAIN_C1);
}

static uint32_t ir0861_code_from_gain(float gain)
{
    /* Inverse of the SMIA model: code = (c0 - g * c1) / (g * m1 - m0). */
    float denominator = gain * (float)IR0861_SENSOR_GAIN_M1 - (float)IR0861_SENSOR_GAIN_M0;
    float code = denominator == 0.0f ? (float)IR0861_SENSOR_GAIN_CODE_MIN :
        ((float)IR0861_SENSOR_GAIN_C0 - gain * (float)IR0861_SENSOR_GAIN_C1) / denominator;
    uint32_t steps;
    if (code < (float)IR0861_SENSOR_GAIN_CODE_MIN) code = (float)IR0861_SENSOR_GAIN_CODE_MIN;
    if (code > (float)IR0861_SENSOR_GAIN_CODE_MAX) code = (float)IR0861_SENSOR_GAIN_CODE_MAX;
    /* Round down to the sensor's step so the real gain never exceeds the request. */
    steps = (uint32_t)(code - (float)IR0861_SENSOR_GAIN_CODE_MIN) / IR0861_SENSOR_GAIN_CODE_STEP;
    return (uint32_t)IR0861_SENSOR_GAIN_CODE_MIN + steps * IR0861_SENSOR_GAIN_CODE_STEP;
}

static int32_t ir0861_calculate_exposure(float gain, uint32_t lines,
                                         struct angler_exposure *out)
{
    union { float f; uint32_t bits; } value = { .f = gain };
    float max_gain = ir0861_gain_from_code(IR0861_SENSOR_GAIN_CODE_MAX);
    float analog;
    uint32_t code;
    if (!out || (value.bits & 0x7f800000u) == 0x7f800000u || gain <= 0.0f)
        return -22;
    if (gain < 1.0f) gain = 1.0f;
    analog = gain > max_gain ? max_gain : gain;
    code = ir0861_code_from_gain(analog);
    if (lines < 4u) lines = 4u;
    if (lines > IR0861_MAX_LINES) lines = IR0861_MAX_LINES;
    out->register_gain = code;
    out->lines = lines;
    out->sensor_digital_gain = 0x100;
    out->sensor_real_gain = ir0861_gain_from_code(code);
    out->sensor_real_digital_gain = 1.0f;
    out->isp_digital_gain = gain / out->sensor_real_gain;
    return 0;
}

static int32_t ir0861_fill_exposure(uint32_t gain, uint32_t digital_gain,
                                    uint32_t lines, uint32_t frame_lines,
                                    int32_t luma, uint32_t hdr,
                                    struct msm_camera_i2c_reg_setting *out)
{
    struct msm_camera_i2c_reg_array *r;
    const uint32_t code_min = IR0861_SENSOR_GAIN_CODE_MIN, code_max = IR0861_SENSOR_GAIN_CODE_MAX;
    (void)digital_gain; (void)luma;
    if (!out || !out->reg_setting || hdr) return -22;
    if (gain < code_min) gain = code_min;
    if (gain > code_max) gain = code_max;
    if (lines < 4u) lines = 4u;
    if (lines > IR0861_MAX_LINES) lines = IR0861_MAX_LINES;
    if (frame_lines < IR0861_FRAME_LINES) frame_lines = IR0861_FRAME_LINES;
    if (frame_lines < lines + IR0861_SENSOR_COARSE_MARGIN)
        frame_lines = lines + IR0861_SENSOR_COARSE_MARGIN;
    if (frame_lines > 65535u) frame_lines = 65535u;
    r = out->reg_setting;
    r[0] = (struct msm_camera_i2c_reg_array){0x0104, 1, 0};
    r[1] = (struct msm_camera_i2c_reg_array){0x0340, frame_lines >> 8, 0};
    r[2] = (struct msm_camera_i2c_reg_array){0x0341, frame_lines & 255u, 0};
    r[3] = (struct msm_camera_i2c_reg_array){0x0202, lines >> 8, 0};
    r[4] = (struct msm_camera_i2c_reg_array){0x0203, lines & 255u, 0};
    r[5] = (struct msm_camera_i2c_reg_array){0x0204, gain >> 8, 0};
    r[6] = (struct msm_camera_i2c_reg_array){0x0205, gain & 255u, 0};
    r[7] = (struct msm_camera_i2c_reg_array){0x0104, 0, 0};
    out->size = 8;
    out->addr_type = MSM_CAMERA_I2C_WORD_ADDR;
    out->data_type = MSM_CAMERA_I2C_BYTE_DATA;
    out->delay = 0;
    return 0;
}

struct angler_sensor_descriptor cityman_ir0861_descriptor = {
    .slave = {
        .sensor_name = "ir0861", .camera_id = CAMERA_2, .slave_addr = 0x6c,
        .i2c_freq_mode = I2C_STANDARD_MODE, .addr_type = MSM_CAMERA_I2C_WORD_ADDR,
        .sensor_id_info = { .sensor_id_reg_addr = 0x0000, .sensor_id = 0x0861 },
        /* CAMT D0 order: rails, clocks/MCLK1, reset high, 3 ms. */
        .power_setting_array = {
            .power_setting_a = {
                POWER(SENSOR_GPIO, SENSOR_GPIO_RESET, GPIO_OUT_LOW, 1),
                POWER(SENSOR_VREG, CAM_VANA, 0, 1),
                POWER(SENSOR_VREG, CAM_VIO, 0, 1),
                POWER(SENSOR_VREG, CAM_V_CUSTOM1, 0, 1),
                POWER(SENSOR_VREG, CAM_VDIG, 0, 1),
                POWER(SENSOR_CLK, SENSOR_CAM_MCLK, IR0861_MCLK, 1),
                POWER(SENSOR_GPIO, SENSOR_GPIO_RESET, GPIO_OUT_HIGH, 10),
            }, .size = 7,
            /* CAMT D3 order. */
            .power_down_setting_a = {
                POWER(SENSOR_GPIO, SENSOR_GPIO_RESET, GPIO_OUT_LOW, 1),
                POWER(SENSOR_CLK, SENSOR_CAM_MCLK, 0, 5),
                POWER(SENSOR_VREG, CAM_VDIG, 0, 0),
                POWER(SENSOR_VREG, CAM_V_CUSTOM1, 0, 1),
                POWER(SENSOR_VREG, CAM_VIO, 0, 1),
                POWER(SENSOR_VREG, CAM_VANA, 0, 10),
            }, .size_down = 6,
        },
        .is_init_params_valid = 1,
        /*
         * Front-facing. Windows writes 0x0101 (mirror/flip) = 0 unless the OEM
         * registry key Rotation\FlipMirror is 1, which gives 3; the Lumia value
         * is not in any public source. Mount angle copied from the front camera:
         * check it on the first image.
         */
        .sensor_init_params = {.modes_supported = CAMERA_MODE_2D_B,
                               .position = FRONT_CAMERA_B, .sensor_mount_angle = 90},
        .is_flash_supported = 0,
    },
    /* Bayer, MIPI, 10 bit; order from 0x0006. The iris die is probably monochrome. */
    .output = {0, 1, 1, IR0861_BAYER_ORDER},
    .output_registers = {0x034c, 0x034e, 0x0342, 0x0340},
    .exposure_registers = {0x0202, 0x0204, IR0861_SENSOR_COARSE_MARGIN},
    .aec = {1.0f, 8.0f, 8.0f, IR0861_MAX_LINES},
    .exposure_start_delay = 1, .exposure_update_delay = 2,
    .lens = {.focal_length = 0.0f, .pixel_pitch = 0.0f, .f_number = 2.4f,
             .sensing_method = 2, .crop_factor = 1.0f,
             .physical_width = 0.0f, .physical_height = 0.0f},
    .active_array = {1920, 1088, 0, 0, 0, 0},
    .white_level = 1023,
    .black_level = {IR0861_SENSOR_PEDESTAL, IR0861_SENSOR_PEDESTAL,
                    IR0861_SENSOR_PEDESTAL, IR0861_SENSOR_PEDESTAL},
    .streams = {.entries = {{.cid_count = 1,
                    .cid = {{0, CSI_RAW10, CSI_DECODE_10BIT}}, .pixel_format = {0}}}, .count = 1},
    .start = SETTING(stream_on, MSM_CAMERA_I2C_BYTE_DATA, 0),
    .stop = SETTING(stream_off, MSM_CAMERA_I2C_BYTE_DATA, 0),
    .group_on = SETTING(hold_on, MSM_CAMERA_I2C_BYTE_DATA, 0),
    .group_off = SETTING(hold_off, MSM_CAMERA_I2C_BYTE_DATA, 0),
    .init = {.entries = {
        SETTING(reset, MSM_CAMERA_I2C_BYTE_DATA, 10),
        SETTING(extclk, MSM_CAMERA_I2C_BYTE_DATA, 0),
        SETTING(ir0861_idle, MSM_CAMERA_I2C_BYTE_DATA, 0),
    }, .count = 3},
    .resolutions = {.entries = {SETTING(ir0861_mode0, MSM_CAMERA_I2C_BYTE_DATA, 0)}, .count = 1},
    /* Same action order as vs6955 (the angler front sensor). */
    .resolution_actions = {{0, 2, 4, 5, 6, 3, 1}, 7},
    .modes = {.entries = {
        {.width = 1920, .height = 1088, .line_length = IR0861_LINE_LENGTH,
         .frame_length = IR0861_FRAME_LINES, .vt_pixel_clock = IR0861_VT_CLOCK,
         .output_pixel_clock = IR0861_OUTPUT_CLOCK, .binning_factor = 1,
         .minimum_fps = 7.5f, .maximum_fps = IR0861_MAX_FPS, .kind = 1},
    }, .count = 1},
    /*
     * PHY2 upper combo pair, verified with LumiaFaceID's diagnostic (12,677 and
     * 12,720 clean packets): lane mask 0x18 (clock 3, data 4), combo mode 1,
     * CSID lane assign 0x0004, settle 22, PHY mux to CSID3.
     */
    .csi = {.entries = {{
        .csid = {.lane_cnt = 1, .lane_assign = 0x0004, .phy_sel = 2,
                 .lut_params = {.num_cid = 1, .vc_cfg_a = {
                     {0, CSI_RAW10, CSI_DECODE_10BIT}}}},
        .phy = {.lane_cnt = 1, .settle_cnt = 22, .lane_mask = 0x18,
                .combo_mode = 1, .csid_core = 3},
    }}, .count = 1},
    .crops = {.entries = {{.top = 0, .bottom = 0, .left = 0, .right = 0}}, .count = 1},
    /*
     * The daemon dereferences these during sensor start; an empty list makes
     * it fault (see vs6955). Angler front (imx179) seeds from the vendor
     * tree: ABI-compatible, not iris tuning.
     */
    .tuning = {.entries = {{.names = {
        "libchromatix_imx179_liteon_common.so",
        "libchromatix_imx179_liteon_preview.so",
        "libchromatix_imx179_liteon_preview.so",
        "libchromatix_imx179_liteon_video_binning.so",
        "libchromatix_imx179_liteon_liveshot.so",
        "libchromatix_imx179_liteon_cpp_preview.so",
        "libchromatix_imx179_liteon_cpp_preview.so",
        "libchromatix_imx179_liteon_cpp_preview.so",
        "libchromatix_imx179_liteon_cpp_video.so",
        0,
        "libchromatix_imx179_liteon_cpp_liveshot.so",
        "libchromatix_imx179_liteon_postproc.so",
    }}}, .count = 1},
    .exposure = {ir0861_calculate_exposure, ir0861_fill_exposure, 0, 0},
    .exposure_table_capacity = 8, .initial_frame_skip = 2,
};

__attribute__((visibility("default"))) void *sensor_open_lib(void)
{
    return &cityman_ir0861_descriptor;
}
