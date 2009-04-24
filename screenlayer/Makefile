CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar

OBJS = ScreenLayer.o

LIBNAME=libIpuScreenLayer

all: $(LIBNAME).so

install:
	@mkdir -p $(DEST_DIR)/usr/lib
	cp $(LIBNAME).* $(DEST_DIR)/usr/lib
	@mkdir -p $(DEST_DIR)/usr/include
	cp ScreenLayer.h $(DEST_DIR)/usr/include

$(LIBNAME).so: $(OBJS)
	$(CC) -shared -nostartfiles -Wl,-soname,$@ -o $@ $^ -L../ipu -lipu

%.o: %.c
	$(CC) $(INCLUDE) -Wall -O2 -c $^ -o $@

.PHONY: clean
clean:
	@rm -f $(OBJS) $(LIBNAME).*
