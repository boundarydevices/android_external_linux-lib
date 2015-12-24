CC ?=$(CROSS_COMPILE)gcc
AR ?=$(CROSS_COMPILE)ar
CFLAGS ?=-O2

OBJ = mxc_hdmi-cec.o

LIBNAME = libcec
SONAMEVERSION=1

all: $(LIBNAME).so $(LIBNAME).a

install: install_headers
	@mkdir -p $(DEST_DIR)/usr/lib
	cp -P $(LIBNAME).* $(DEST_DIR)/usr/lib

install_headers:
	@mkdir -p $(DEST_DIR)/usr/include
	cp hdmi-cec.h $(DEST_DIR)/usr/include

%.o: %.c
	$(CC) -D$(PLATFORM) -Wall -fPIC $(CFLAGS) -c $^ -o $@

$(LIBNAME).so.$(SONAMEVERSION): $(OBJ)
	$(CC) -shared -nostartfiles -Wl,-soname,$@ $^ -o $@ $(LDFLAGS)

$(LIBNAME).so: $(LIBNAME).so.$(SONAMEVERSION)
	ln -s $< $@

$(LIBNAME).a: $(OBJ)
	$(AR) -rc $@  $^

.PHONY: clean
clean:
	rm -f $(LIBNAME).* $(OBJ)
