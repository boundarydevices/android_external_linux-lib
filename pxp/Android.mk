LOCAL_PATH := $(call my-dir)

# Share library
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	pxp_lib.c

LOCAL_SHARED_LIBRARIES := libutils libc liblog

LOCAL_C_INCLUDES += $(LOCAL_PATH)
LOCAL_MODULE := libpxp
LOCAL_PRELINK_MODULE := false
LOCAL_MODULE_TAGS := eng
include $(BUILD_SHARED_LIBRARY)

