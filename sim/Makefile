CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar

OBJS = iso7816-3.o

CFLAGS += $(INCLUDE)

LIBNAME=libsim
SONAMEVERSION=0

# list of platforms which want this test case
INCLUDE_LIST:= IMX51 IMX25_3STACK

ifeq ($(PLATFORM), $(findstring $(PLATFORM), $(INCLUDE_LIST)))
all: $(LIBNAME).so

install:
	@mkdir -p $(DEST_DIR)/usr/lib
	cp -P $(LIBNAME).* $(DEST_DIR)/usr/lib
	@mkdir -p $(DEST_DIR)/usr/include
	cp iso7816-3.h $(DEST_DIR)/usr/include

$(LIBNAME).so.$(SONAMEVERSION): $(OBJS)
	$(CC) -shared -nostartfiles -Wl,-soname,$@ -o $@ $^ -lpthread

$(LIBNAME).so: $(LIBNAME).so.$(SONAMEVERSION)
	ln -s $< $@

%.o: %.c
	$(CC) -D$(PLATFORM) $(INCLUDE) -Wall -O2 -fPIC -c $^ -o $@

else
all install :
endif

.PHONY: clean
clean:
	@rm -f $(OBJS) $(LIBNAME).*
