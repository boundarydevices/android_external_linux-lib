ifeq ($(BOARD_HAVE_HDMI),true)

LOCAL_PATH := $(call my-dir)

# Share library
include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
	mxc_hdmi-cec.c
ifeq ($(BOARD_SOC_CLASS),IMX6)
LOCAL_CFLAGS += -DBUILD_FOR_ANDROID -DIMX6Q
else
LOCAL_CFLAGS += -DBUILD_FOR_ANDROID -D$(BOARD_SOC_TYPE)
endif
LOCAL_C_INCLUDES += $(LOCAL_PATH)
LOCAL_SHARED_LIBRARIES := libutils libc liblog
LOCAL_MODULE := libcec
LOCAL_LD_FLAGS += -nostartfiles
LOCAL_PRELINK_MODULE := false
LOCAL_MODULE_TAGS := eng
include $(BUILD_SHARED_LIBRARY)

endif
