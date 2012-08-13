ifeq ($(BOARD_HAVE_VPU),true)

LOCAL_PATH := $(call my-dir)

# Share library
include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
	vpu_io.c \
	vpu_util.c \
	vpu_lib.c \
	vpu_gdi.c
ifeq ($(BOARD_SOC_CLASS),IMX6)
LOCAL_CFLAGS += -DBUILD_FOR_ANDROID -DIMX6Q
else
LOCAL_CFLAGS += -DBUILD_FOR_ANDROID -D$(BOARD_SOC_TYPE)
endif
ifeq ($(USE_GPU_ALLOCATOR), true)
LOCAL_CFLAGS += -DUSE_GPU=1
LOCAL_SHARED_LIBRARIES := libutils libc liblog libGAL
else
ifeq ($(USE_ION_ALLOCATOR), true)
LOCAL_CFLAGS += -DUSE_ION
LOCAL_SHARED_LIBRARIES := libutils libc liblog libion
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../../../hardware/imx/ion/
else
LOCAL_SHARED_LIBRARIES := libutils libc liblog
endif
endif
LOCAL_C_INCLUDES += $(LOCAL_PATH)
LOCAL_MODULE := libvpu
LOCAL_LD_FLAGS += -nostartfiles
LOCAL_PRELINK_MODULE := false
LOCAL_MODULE_TAGS := eng
include $(BUILD_SHARED_LIBRARY)

endif
