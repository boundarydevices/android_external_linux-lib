CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar
INC = $(INCLUDE) -I../ipu

OBJS = ScreenLayer.o

# list of platforms which want this test case
INCLUDE_LIST:= IMX37_3STACK IMX51 IMX53

LIBNAME=libIpuScreenLayer
SONAMEVERSION=0

ifeq ($(PLATFORM), $(findstring $(PLATFORM), $(INCLUDE_LIST)))
all: $(LIBNAME).so

install:
	@mkdir -p $(DEST_DIR)/usr/lib
	cp -P $(LIBNAME).* $(DEST_DIR)/usr/lib
	@mkdir -p $(DEST_DIR)/usr/include
	cp ScreenLayer.h $(DEST_DIR)/usr/include
else
all install:
	@echo "Not support platform, will not complile"
endif

$(LIBNAME).so.$(SONAMEVERSION): $(OBJS)
	$(CC) -shared -nostartfiles -Wl,-soname,$@ -o $@ $^ -L../ipu -lipu

$(LIBNAME).so: $(LIBNAME).so.$(SONAMEVERSION)
	ln -s $< $@

%.o: %.c
	$(CC) $(INC) -Wall -O2 -fPIC -c $^ -o $@

.PHONY: clean
clean:
	@rm -f $(OBJS) $(LIBNAME).*
