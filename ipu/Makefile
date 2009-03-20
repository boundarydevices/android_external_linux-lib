CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar

OBJS = mxc_ipu_hl_lib.o mxc_ipu_lib.o

LIBNAME=libipu

all: $(LIBNAME).so

install:
	@mkdir -p $(DEST_DIR)/usr/lib
	cp $(LIBNAME).* $(DEST_DIR)/usr/lib
	@mkdir -p $(DEST_DIR)/usr/include
	cp mxc_ipu_hl_lib.h $(DEST_DIR)/usr/include

$(LIBNAME).so: $(OBJS)
	$(CC) -shared -nostartfiles -Wl,-soname,$@ -o $@ $^ -lpthread

%.o: %.c
ifeq "$(PLATFORM)" ""
	$(error "Unspecified PLATFORM variable")
endif
	$(CC) -D$(PLATFORM) $(INCLUDE) -Wall -O2 -c $^ -o $@

.PHONY: clean
clean:
	@rm -f $(OBJS) $(LIBNAME).*
