CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar

ifeq ($(PLATFORM), IMX6Q)
OBJS = mxc_ipu_hl_lib_dummy.o
else
OBJS = mxc_ipu_hl_lib.o mxc_ipu_lib.o
endif

# list of platforms which want this test case
INCLUDE_LIST:= IMX37_3STACK IMX51 IMX53 IMX6Q

LIBNAME=libipu
SONAMEVERSION=0

ifeq ($(PLATFORM), $(findstring $(PLATFORM), $(INCLUDE_LIST)))
all: $(LIBNAME).so

install:
	@mkdir -p $(DEST_DIR)/usr/lib
	cp -P $(LIBNAME).* $(DEST_DIR)/usr/lib
	@mkdir -p $(DEST_DIR)/usr/include
	cp mxc_ipu_hl_lib.h $(DEST_DIR)/usr/include
	cp ipu.h $(DEST_DIR)/usr/include
else
all install:
	@echo "Not support platform, will not complile"
endif

$(LIBNAME).so.$(SONAMEVERSION): $(OBJS)
	$(CC) -shared -nostartfiles -Wl,-soname,$@ -o $@ $^ -lpthread

$(LIBNAME).so: $(LIBNAME).so.$(SONAMEVERSION)
	ln -s $< $@

%.o: %.c
ifeq "$(PLATFORM)" ""
	$(error "Unspecified PLATFORM variable")
endif
	$(CC) -D$(PLATFORM) $(INCLUDE) -Wall -O2 -fPIC -c $^ -o $@

.PHONY: clean
clean:
	@rm -f $(OBJS) $(LIBNAME).*
