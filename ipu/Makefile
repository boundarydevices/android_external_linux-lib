CC ?=$(CROSS_COMPILE)gcc
AR ?=$(CROSS_COMPILE)ar
CFLAGS ?=-O2

ifeq ($(PLATFORM), IMX6Q)
OBJS = mxc_ipu_hl_lib_dummy.o
else
OBJS = mxc_ipu_hl_lib.o mxc_ipu_lib.o
endif


LIBNAME=libipu
SONAMEVERSION=0

all: $(LIBNAME).so

install:
	@mkdir -p $(DEST_DIR)/usr/lib
	cp -P $(LIBNAME).* $(DEST_DIR)/usr/lib
	@mkdir -p $(DEST_DIR)/usr/include
	cp mxc_ipu_hl_lib.h $(DEST_DIR)/usr/include
	cp ipu.h $(DEST_DIR)/usr/include

$(LIBNAME).so.$(SONAMEVERSION): $(OBJS)
	$(CC) -shared -nostartfiles -Wl,-soname,$@ -o $@ $^ $(LDFLAGS)

$(LIBNAME).so: $(LIBNAME).so.$(SONAMEVERSION)
	ln -s $< $@

%.o: %.c
ifeq "$(PLATFORM)" ""
	$(error "Unspecified PLATFORM variable")
endif
	$(CC) -D$(PLATFORM) $(INCLUDE) -Wall -fPIC $(CFLAGS) -c $^ -o $@

.PHONY: clean
clean:
	@rm -f $(OBJS) $(LIBNAME).*
