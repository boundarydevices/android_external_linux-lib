ifeq ($(HAVE_FSL_IMX_IPU),true)
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

ifeq ($(BOARD_SOC_CLASS),IMX5X)
LOCAL_SRC_FILES := \
	mxc_ipu_hl_lib.c \
	mxc_ipu_lib.c
else
LOCAL_SRC_FILES := \
	mxc_ipu_hl_lib_dummy.c
endif

LOCAL_CFLAGS += -DBUILD_FOR_ANDROID

LOCAL_C_INCLUDES += $(LOCAL_PATH)

LOCAL_SHARED_LIBRARIES := libutils libc libcutils

LOCAL_MODULE := libipu
LOCAL_LD_FLAGS += -nostartfiles
LOCAL_PRELINK_MODULE := false
LOCAL_MODULE_TAGS := eng
include $(BUILD_SHARED_LIBRARY)
endif
