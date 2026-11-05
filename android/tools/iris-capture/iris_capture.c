// SPDX-License-Identifier: GPL-2.0-only
/*
 * iris_capture: open one explicit Camera2 ID through the NDK and save a few
 * frames. Made for the cityman iris, which no camera app can select on its
 * own because it shares the "front" facing with the vs6955. The numeric ID
 * changes between boots (2 on the temporary boot, 1 once flashed), so without
 * -c the tool picks the unique camera with a 1920x1088 pixel array.
 *
 *   iris_capture -l                      list cameras, formats and ranges
 *   iris_capture [-c id] [-n 5] [-f raw10|raw16|yuv] [-e exposure_us]
 *                [-s iso] [-t timeout_s] [-o /data/local/tmp]
 *
 * Run as root (adb root): cameraserver then grants the CAMERA permission.
 * The flash is always forced off. Nothing here touches LEDs or the kernel.
 * Without -e the HAL's AE runs. With -e, AE is switched off and -s (default
 * 100) is used as sensitivity.
 */
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <camera/NdkCameraCaptureSession.h>
#include <camera/NdkCameraDevice.h>
#include <camera/NdkCameraManager.h>
#include <camera/NdkCameraMetadata.h>
#include <camera/NdkCaptureRequest.h>
#include <media/NdkImage.h>
#include <media/NdkImageReader.h>

#define MAX_IMAGES 4

struct state {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int wanted, saved, completed, failed, device_error;
    int32_t format;
    const char *dir;
};

static struct state st = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER,
};

static const char *format_name(int32_t format)
{
    switch (format) {
    case AIMAGE_FORMAT_RAW10: return "raw10";
    case AIMAGE_FORMAT_RAW16: return "raw16";
    case AIMAGE_FORMAT_YUV_420_888: return "yuv";
    case AIMAGE_FORMAT_RAW_PRIVATE: return "raw_private";
    case AIMAGE_FORMAT_JPEG: return "jpeg";
    case AIMAGE_FORMAT_PRIVATE: return "private";
    default: return "other";
    }
}

static void signal_state(void)
{
    pthread_cond_broadcast(&st.cond);
}

/* Min / max / mean of the first plane, in sensor units (10/16 bit, or Y). */
static void plane_stats(const uint8_t *data, int32_t width, int32_t height, int32_t stride,
                        uint32_t *min, uint32_t *max, double *mean)
{
    uint64_t sum = 0;
    *min = UINT32_MAX;
    *max = 0;
    for (int32_t y = 0; y < height; y++) {
        const uint8_t *row = data + (size_t)y * (size_t)stride;
        for (int32_t x = 0; x < width; x++) {
            uint32_t v;
            if (st.format == AIMAGE_FORMAT_RAW10) {
                /* MIPI RAW10: 4 pixels in 5 bytes, low bits in byte 4. */
                const uint8_t *g = row + (x / 4) * 5;
                v = ((uint32_t)g[x % 4] << 2) | ((g[4] >> (2 * (x % 4))) & 3u);
            } else if (st.format == AIMAGE_FORMAT_RAW16) {
                v = (uint32_t)row[2 * x] | ((uint32_t)row[2 * x + 1] << 8);
            } else {
                v = row[x];
            }
            if (v < *min) *min = v;
            if (v > *max) *max = v;
            sum += v;
        }
    }
    *mean = width && height ? (double)sum / ((double)width * (double)height) : 0.0;
}

static void on_image(void *context, AImageReader *reader)
{
    AImage *image = NULL;
    (void)context;
    if (AImageReader_acquireNextImage(reader, &image) != AMEDIA_OK || !image)
        return;

    pthread_mutex_lock(&st.lock);
    int index = st.saved < st.wanted ? st.saved++ : -1;
    pthread_mutex_unlock(&st.lock);

    if (index >= 0) {
        int64_t timestamp = 0;
        int32_t width = 0, height = 0, stride = 0;
        uint8_t *data = NULL;
        int length = 0;
        AImage_getTimestamp(image, &timestamp);
        AImage_getWidth(image, &width);
        AImage_getHeight(image, &height);
        AImage_getPlaneRowStride(image, 0, &stride);
        if (AImage_getPlaneData(image, 0, &data, &length) == AMEDIA_OK && data) {
            char path[512];
            uint32_t min, max;
            double mean;
            snprintf(path, sizeof(path), "%s/iris-%d.%s", st.dir, index, format_name(st.format));
            FILE *f = fopen(path, "wb");
            if (f) {
                fwrite(data, 1, (size_t)length, f);
                fclose(f);
            }
            plane_stats(data, width, height, stride, &min, &max, &mean);
            printf("frame %d: %dx%d stride=%d bytes=%d ts=%" PRId64 " min=%u max=%u mean=%.1f -> %s%s\n",
                   index, width, height, stride, length, timestamp, min, max, mean, path,
                   f ? "" : " (write failed)");
            fflush(stdout);
        }
    }
    AImage_delete(image);
    pthread_mutex_lock(&st.lock);
    signal_state();
    pthread_mutex_unlock(&st.lock);
}

static void on_completed(void *context, ACameraCaptureSession *session,
                         ACaptureRequest *request, const ACameraMetadata *result)
{
    ACameraMetadata_const_entry e;
    int64_t exposure = -1;
    int32_t iso = -1;
    (void)context; (void)session; (void)request;
    if (ACameraMetadata_getConstEntry(result, ACAMERA_SENSOR_EXPOSURE_TIME, &e) == ACAMERA_OK && e.count)
        exposure = e.data.i64[0];
    if (ACameraMetadata_getConstEntry(result, ACAMERA_SENSOR_SENSITIVITY, &e) == ACAMERA_OK && e.count)
        iso = e.data.i32[0];
    pthread_mutex_lock(&st.lock);
    int n = st.completed++;
    pthread_mutex_unlock(&st.lock);
    if (n < 3)
        printf("result %d: exposure_ns=%" PRId64 " sensitivity=%d\n", n, exposure, iso);
}

static void on_failed(void *context, ACameraCaptureSession *session,
                      ACaptureRequest *request, ACameraCaptureFailure *failure)
{
    (void)context; (void)session; (void)request;
    pthread_mutex_lock(&st.lock);
    int n = st.failed++;
    pthread_mutex_unlock(&st.lock);
    if (n < 5)
        printf("capture failed: frame=%" PRId64 " reason=%d image_captured=%d\n",
               failure->frameNumber, failure->reason, failure->wasImageCaptured);
}

static void on_device_disconnected(void *context, ACameraDevice *device)
{
    (void)context; (void)device;
    printf("device disconnected\n");
    pthread_mutex_lock(&st.lock);
    st.device_error = -1;
    signal_state();
    pthread_mutex_unlock(&st.lock);
}

static void on_device_error(void *context, ACameraDevice *device, int error)
{
    (void)context; (void)device;
    printf("device error %d\n", error);
    pthread_mutex_lock(&st.lock);
    st.device_error = error ? error : -1;
    signal_state();
    pthread_mutex_unlock(&st.lock);
}

static void on_session_closed(void *c, ACameraCaptureSession *s) { (void)c; (void)s; }
static void on_session_ready(void *c, ACameraCaptureSession *s) { (void)c; (void)s; }
static void on_session_active(void *c, ACameraCaptureSession *s) { (void)c; (void)s; }

static bool has_output(const ACameraMetadata *chars, int32_t format, int32_t *width, int32_t *height)
{
    ACameraMetadata_const_entry e;
    bool found = false;
    if (ACameraMetadata_getConstEntry(chars, ACAMERA_SCALER_AVAILABLE_STREAM_CONFIGURATIONS, &e) != ACAMERA_OK)
        return false;
    for (uint32_t i = 0; i + 3 < e.count; i += 4) {
        const int32_t *c = e.data.i32 + i;
        if (c[0] != format || c[3] != ACAMERA_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT)
            continue;
        /* Keep the largest size for this format. */
        if (!found || (int64_t)c[1] * c[2] > (int64_t)*width * *height) {
            *width = c[1];
            *height = c[2];
            found = true;
        }
    }
    return found;
}

static void list_cameras(ACameraManager *manager)
{
    ACameraIdList *ids = NULL;
    if (ACameraManager_getCameraIdList(manager, &ids) != ACAMERA_OK || !ids) {
        printf("getCameraIdList failed\n");
        return;
    }
    for (int i = 0; i < ids->numCameras; i++) {
        const char *id = ids->cameraIds[i];
        ACameraMetadata *chars = NULL;
        ACameraMetadata_const_entry e;
        if (ACameraManager_getCameraCharacteristics(manager, id, &chars) != ACAMERA_OK || !chars) {
            printf("camera %s: no characteristics\n", id);
            continue;
        }
        printf("camera %s:", id);
        if (ACameraMetadata_getConstEntry(chars, ACAMERA_LENS_FACING, &e) == ACAMERA_OK && e.count)
            printf(" facing=%s", e.data.u8[0] == ACAMERA_LENS_FACING_FRONT ? "front" :
                   e.data.u8[0] == ACAMERA_LENS_FACING_BACK ? "back" : "external");
        if (ACameraMetadata_getConstEntry(chars, ACAMERA_SENSOR_INFO_PIXEL_ARRAY_SIZE, &e) == ACAMERA_OK && e.count >= 2)
            printf(" pixel_array=%dx%d", e.data.i32[0], e.data.i32[1]);
        if (ACameraMetadata_getConstEntry(chars, ACAMERA_SENSOR_INFO_COLOR_FILTER_ARRANGEMENT, &e) == ACAMERA_OK && e.count)
            printf(" cfa=%u", e.data.u8[0]);
        if (ACameraMetadata_getConstEntry(chars, ACAMERA_SENSOR_INFO_EXPOSURE_TIME_RANGE, &e) == ACAMERA_OK && e.count >= 2)
            printf(" exposure_ns=%" PRId64 "..%" PRId64, e.data.i64[0], e.data.i64[1]);
        if (ACameraMetadata_getConstEntry(chars, ACAMERA_SENSOR_INFO_SENSITIVITY_RANGE, &e) == ACAMERA_OK && e.count >= 2)
            printf(" iso=%d..%d", e.data.i32[0], e.data.i32[1]);
        if (ACameraMetadata_getConstEntry(chars, ACAMERA_REQUEST_AVAILABLE_CAPABILITIES, &e) == ACAMERA_OK) {
            printf(" caps=");
            for (uint32_t j = 0; j < e.count; j++)
                printf("%s%u", j ? "," : "", e.data.u8[j]);
        }
        printf("\n");
        if (ACameraMetadata_getConstEntry(chars, ACAMERA_SCALER_AVAILABLE_STREAM_CONFIGURATIONS, &e) == ACAMERA_OK) {
            for (uint32_t j = 0; j + 3 < e.count; j += 4) {
                const int32_t *c = e.data.i32 + j;
                if (c[3] == ACAMERA_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT)
                    printf("  output %s(0x%x) %dx%d\n", format_name(c[0]), c[0], c[1], c[2]);
            }
        }
        ACameraMetadata_free(chars);
    }
    ACameraManager_deleteCameraIdList(ids);
}

/* The iris is the only camera with a 1920x1088 pixel array. */
static char *find_iris(ACameraManager *manager)
{
    ACameraIdList *ids = NULL;
    char *found = NULL;
    int matches = 0;
    if (ACameraManager_getCameraIdList(manager, &ids) != ACAMERA_OK || !ids)
        return NULL;
    for (int i = 0; i < ids->numCameras; i++) {
        ACameraMetadata *chars = NULL;
        ACameraMetadata_const_entry e;
        if (ACameraManager_getCameraCharacteristics(manager, ids->cameraIds[i], &chars) != ACAMERA_OK || !chars)
            continue;
        if (ACameraMetadata_getConstEntry(chars, ACAMERA_SENSOR_INFO_PIXEL_ARRAY_SIZE, &e) == ACAMERA_OK &&
            e.count >= 2 && e.data.i32[0] == 1920 && e.data.i32[1] == 1088) {
            matches++;
            if (!found)
                found = strdup(ids->cameraIds[i]);
        }
        ACameraMetadata_free(chars);
    }
    ACameraManager_deleteCameraIdList(ids);
    if (matches != 1) {
        printf("found %d cameras with a 1920x1088 pixel array; pass -c explicitly\n", matches);
        free(found);
        return NULL;
    }
    return found;
}

static void usage(const char *name)
{
    fprintf(stderr, "usage: %s -l | [-c id] [-n frames] [-f raw10|raw16|yuv] [-e exposure_us] "
            "[-s iso] [-t timeout_s] [-o dir]\n", name);
}

int main(int argc, char **argv)
{
    const char *id = NULL, *want_format = NULL;
    char *auto_id = NULL;
    int frames = 5, timeout_s = 10, opt, rc = 1;
    int64_t exposure_us = 0;
    int32_t iso = 100, width = 0, height = 0;
    bool list = false;

    st.dir = "/data/local/tmp";
    while ((opt = getopt(argc, argv, "lc:n:f:e:s:t:o:")) != -1) {
        switch (opt) {
        case 'l': list = true; break;
        case 'c': id = optarg; break;
        case 'n': frames = atoi(optarg); break;
        case 'f': want_format = optarg; break;
        case 'e': exposure_us = atoll(optarg); break;
        case 's': iso = atoi(optarg); break;
        case 't': timeout_s = atoi(optarg); break;
        case 'o': st.dir = optarg; break;
        default: usage(argv[0]); return 2;
        }
    }
    if (frames < 1 || frames > 100 || timeout_s < 1 || timeout_s > 120 || exposure_us < 0) {
        usage(argv[0]);
        return 2;
    }

    ACameraManager *manager = ACameraManager_create();
    if (!manager) {
        printf("ACameraManager_create failed\n");
        return 1;
    }
    if (list) {
        list_cameras(manager);
        ACameraManager_delete(manager);
        return 0;
    }

    if (!id) {
        auto_id = find_iris(manager);
        if (!auto_id) {
            ACameraManager_delete(manager);
            return 1;
        }
        id = auto_id;
        printf("iris is camera %s\n", id);
    }

    ACameraMetadata *chars = NULL;
    camera_status_t cs = ACameraManager_getCameraCharacteristics(manager, id, &chars);
    if (cs != ACAMERA_OK || !chars) {
        printf("camera %s: characteristics failed (%d)\n", id, cs);
        free(auto_id);
        ACameraManager_delete(manager);
        return 1;
    }

    static const struct { const char *name; int32_t format; } formats[] = {
        {"raw10", AIMAGE_FORMAT_RAW10}, {"raw16", AIMAGE_FORMAT_RAW16},
        {"yuv", AIMAGE_FORMAT_YUV_420_888},
    };
    st.format = 0;
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); i++) {
        if (want_format && strcmp(want_format, formats[i].name))
            continue;
        if (has_output(chars, formats[i].format, &width, &height)) {
            st.format = formats[i].format;
            break;
        }
    }
    ACameraMetadata_free(chars);
    if (!st.format) {
        printf("camera %s: no output for %s (see -l)\n", id, want_format ? want_format : "raw10/raw16/yuv");
        free(auto_id);
        ACameraManager_delete(manager);
        return 1;
    }
    st.wanted = frames;
    printf("camera %s: %s %dx%d, %d frames, timeout %d s\n", id, format_name(st.format),
           width, height, frames, timeout_s);

    AImageReader *reader = NULL;
    ANativeWindow *window = NULL;
    ACameraDevice *device = NULL;
    ACaptureSessionOutputContainer *outputs = NULL;
    ACaptureSessionOutput *output = NULL;
    ACameraCaptureSession *session = NULL;
    ACaptureRequest *request = NULL;
    ACameraOutputTarget *target = NULL;
    bool repeating = false;

    AImageReader_ImageListener image_listener = { .context = NULL, .onImageAvailable = on_image };
    ACameraDevice_StateCallbacks device_cb = {
        .context = NULL, .onDisconnected = on_device_disconnected, .onError = on_device_error,
    };
    ACameraCaptureSession_stateCallbacks session_cb = {
        .context = NULL, .onClosed = on_session_closed, .onReady = on_session_ready,
        .onActive = on_session_active,
    };
    ACameraCaptureSession_captureCallbacks capture_cb = {
        .context = NULL, .onCaptureCompleted = on_completed, .onCaptureFailed = on_failed,
    };

    if (AImageReader_new(width, height, st.format, MAX_IMAGES, &reader) != AMEDIA_OK ||
        AImageReader_setImageListener(reader, &image_listener) != AMEDIA_OK ||
        AImageReader_getWindow(reader, &window) != AMEDIA_OK) {
        printf("image reader set-up failed\n");
        goto out;
    }
    cs = ACameraManager_openCamera(manager, id, &device_cb, &device);
    if (cs != ACAMERA_OK) {
        printf("openCamera %s failed (%d)%s\n", id, cs,
               cs == ACAMERA_ERROR_PERMISSION_DENIED ? ": run as root (adb root)" : "");
        goto out;
    }
    if (ACaptureSessionOutputContainer_create(&outputs) != ACAMERA_OK ||
        ACaptureSessionOutput_create(window, &output) != ACAMERA_OK ||
        ACaptureSessionOutputContainer_add(outputs, output) != ACAMERA_OK) {
        printf("output set-up failed\n");
        goto out;
    }
    cs = ACameraDevice_createCaptureSession(device, outputs, &session_cb, &session);
    if (cs != ACAMERA_OK) {
        printf("createCaptureSession failed (%d)\n", cs);
        goto out;
    }
    if (ACameraDevice_createCaptureRequest(device, TEMPLATE_PREVIEW, &request) != ACAMERA_OK ||
        ACameraOutputTarget_create(window, &target) != ACAMERA_OK ||
        ACaptureRequest_addTarget(request, target) != ACAMERA_OK) {
        printf("request set-up failed\n");
        goto out;
    }
    {
        uint8_t flash = ACAMERA_FLASH_MODE_OFF;
        ACaptureRequest_setEntry_u8(request, ACAMERA_FLASH_MODE, 1, &flash);
        if (exposure_us) {
            uint8_t ae = ACAMERA_CONTROL_AE_MODE_OFF;
            int64_t exposure_ns = exposure_us * 1000;
            ACaptureRequest_setEntry_u8(request, ACAMERA_CONTROL_AE_MODE, 1, &ae);
            ACaptureRequest_setEntry_i64(request, ACAMERA_SENSOR_EXPOSURE_TIME, 1, &exposure_ns);
            ACaptureRequest_setEntry_i32(request, ACAMERA_SENSOR_SENSITIVITY, 1, &iso);
        } else {
            uint8_t ae = ACAMERA_CONTROL_AE_MODE_ON;
            ACaptureRequest_setEntry_u8(request, ACAMERA_CONTROL_AE_MODE, 1, &ae);
        }
    }
    cs = ACameraCaptureSession_setRepeatingRequest(session, &capture_cb, 1, &request, NULL);
    if (cs != ACAMERA_OK) {
        printf("setRepeatingRequest failed (%d)\n", cs);
        goto out;
    }
    repeating = true;

    {
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += timeout_s;
        pthread_mutex_lock(&st.lock);
        while (st.saved < st.wanted && !st.device_error) {
            if (pthread_cond_timedwait(&st.cond, &st.lock, &deadline) == ETIMEDOUT)
                break;
        }
        printf("summary: saved=%d/%d results=%d failed=%d device_error=%d\n",
               st.saved, st.wanted, st.completed, st.failed, st.device_error);
        rc = st.saved == st.wanted ? 0 : 1;
        pthread_mutex_unlock(&st.lock);
    }

out:
    if (repeating)
        ACameraCaptureSession_stopRepeating(session);
    if (session)
        ACameraCaptureSession_close(session);
    if (target)
        ACameraOutputTarget_free(target);
    if (request)
        ACaptureRequest_free(request);
    if (output)
        ACaptureSessionOutput_free(output);
    if (outputs)
        ACaptureSessionOutputContainer_free(outputs);
    if (device)
        ACameraDevice_close(device);
    if (reader)
        AImageReader_delete(reader);
    free(auto_id);
    ACameraManager_delete(manager);
    return rc;
}
