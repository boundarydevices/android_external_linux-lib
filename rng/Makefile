EXCLUDE_LIST:= IMX6Q IMX6S

ifeq (,$(findstring $(PLATFORM), $(EXCLUDE_LIST)))
AR = ar -crv
RM = rm -f
CC ?=$(CROSS_COMPILE)gcc
LD ?=$(CROSS_COMPILE)ld
CFLAGS ?=-g

INC := $(INCLUDE)

# Add compilation checks
override CFLAGS += -Wall -W -Wmissing-prototypes -Wstrict-prototypes -Wdeclaration-after-statement -fPIC

# In absence of kernel CONFIG flags, set API library to build on
# 'unknown' platform.
override CFLAGS += -DFSL_PLATFORM_OTHER -DFSL_HAVE_RNGC $(INC)

OBJS= fsl_shw_rand.o  fsl_shw_hash.o  fsl_shw_sym.o  fsl_shw_user.o         \
		fsl_shw_keystore.o fsl_shw_auth.o  fsl_shw_hmac.o  fsl_shw_wrap.o

LIBNAME=libfsl_shw
SONAMEVERSION=0

all: $(LIBNAME).so $(LIBNAME).a

install: install_headers
	@mkdir -p $(DEST_DIR)/usr/lib
	cp -P $(LIBNAME).* $(DEST_DIR)/usr/lib

install_headers:
	@mkdir -p $(DEST_DIR)/usr/include

$(LIBNAME).a: $(OBJS)
	$(AR) $@ $^

$(LIBNAME).so.$(SONAMEVERSION): $(OBJS)
	$(CC) -shared -nostartfiles -Wl,-soname,$@ -o $@ $^ $(LDFLAGS)

$(LIBNAME).so: $(LIBNAME).so.$(SONAMEVERSION)
	ln -s $< $@

.PHONY: clean
clean:
	@rm -f *.o $(LIBNAME).*

# The keystore file is located in the Sahara directory
fsl_shw_keystore.o: ../sahara2/fsl_shw_keystore.c
	$(CC) $(CFLAGS) -c ../sahara2/fsl_shw_keystore.c

else
OBJS =
all: ${OBJS}
install: ${OBJS}
endif
