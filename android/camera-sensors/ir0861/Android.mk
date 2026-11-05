LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

# Copy this directory next to camera-sensors/vs6955 in
# giannoccarol/android_device_msft_cityman; it uses ../imx230/angler_sensor_abi.h.
ifeq ($(CITYMAN_CAMERA_IRIS),true)
LOCAL_MODULE := libmmcamera_ir0861
LOCAL_MODULE_CLASS := SHARED_LIBRARIES
LOCAL_SRC_FILES := sensor_lib_ir0861.c
LOCAL_CFLAGS := -std=gnu11 -Wall -Wextra -Werror -fvisibility=hidden
ifeq ($(CITYMAN_CAMERA_IRIS_WINDOWS_AE),true)
LOCAL_CFLAGS += -DIR0861_WINDOWS_AE_LIMITS=1
endif
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../imx230 $(TARGET_KERNEL_SOURCE)/include
ifeq ($(strip $(CITYMAN_CAMERA_IRIS_PROFILE)),)
$(error ir0861 requires CITYMAN_CAMERA_IRIS_PROFILE pointing to the private cityman-iris-stream-profile.hex)
endif
cityman_iris_header := $(call local-generated-sources-dir)/ir0861_registers.generated.h
LOCAL_GENERATED_SOURCES += $(cityman_iris_header)
LOCAL_C_INCLUDES += $(dir $(cityman_iris_header))
$(cityman_iris_header): PRIVATE_PROFILE := $(CITYMAN_CAMERA_IRIS_PROFILE)
$(cityman_iris_header): PRIVATE_GENERATOR := $(LOCAL_PATH)/generate-ir0861.py
$(cityman_iris_header): $(CITYMAN_CAMERA_IRIS_PROFILE) $(LOCAL_PATH)/generate-ir0861.py
	python3 $(PRIVATE_GENERATOR) "$(PRIVATE_PROFILE)" "$@"
LOCAL_VENDOR_MODULE := true
LOCAL_32_BIT_ONLY := true
include $(BUILD_SHARED_LIBRARY)
endif
