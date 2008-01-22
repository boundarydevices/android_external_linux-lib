CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar


SOURCE = vpu_io.c vpu_util.c \
	vpu_lib.c

OBJ = vpu_io.o vpu_util.o \
	vpu_lib.o

LIBNAME = libvpu

all: $(LIBNAME).so $(LIBNAME).a

install: install_headers
	@mkdir -p $(DEST_DIR)/usr/lib
	cp $(LIBNAME).* $(DEST_DIR)/usr/lib

install_headers:
	@mkdir -p $(DEST_DIR)/usr/include
	cp vpu_lib.h $(DEST_DIR)/usr/include
	cp vpu_io.h $(DEST_DIR)/usr/include

%.o: %.c
ifeq "$(PLATFORM)" "" 
	$(error "you must specify PLATFORM variable")
endif
	$(CC) -D$(PLATFORM) -Wall -O2 -c $^ -o $@

$(LIBNAME).so: $(OBJ)
	$(CC) -shared -nostartfiles -Wl,-soname,$@ $^ -o $@

$(LIBNAME).a: $(OBJ)
	$(AR) -rc $@  $^

.PHONY: clean
clean:
	rm -f $(LIBNAME).* $(OBJ)
