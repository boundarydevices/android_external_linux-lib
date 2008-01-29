# +FHDR-----------------------------------------------------------------------
# Copyright (c) 2005, Freescale Semiconductor, Inc.
# ----------------------------------------------------------------------------
# FILE NAME      : $RCSfile: Makefile,v $
# DEPARTMENT     : Security Technology Center (STC), NCSG
# ----------------------------------------------------------------------------
# KEYWORDS : SHW, crypto, sahara
# ----------------------------------------------------------------------------
# PURPOSE: Makefile for API Library for Sahara Crypto Accelerator
# -FHDR-----------------------------------------------------------------------

AR = ar -crv
RM = rm -f

INC := $(INCLUDE)

DIAGS=

ifeq ("$(PLATFORM)", "MXC27530EVB")
TARGET_ARCH=-DCONFIG_ARCH_MXC91231
endif
ifeq ("$(PLATFORM)", "MXC30030ADS")
TARGET_ARCH=-DCONFIG_ARCH_MXC91321
endif
ifeq ("$(PLATFORM)", "MXC30030EVB")
TARGET_ARCH=-DCONFIG_ARCH_MXC91321
endif
ifeq ("$(PLATFORM)", "IMX27ADS")
TARGET_ARCH=-DCONFIG_ARCH_MX27
endif
ifeq ("$(PLATFORM)", "MXC30031ADS")
TARGET_ARCH=-DCONFIG_ARCH_MXC92323
endif

# Add compilation checks
CFLAGS += -g -Wall -W -Wmissing-prototypes -Wstrict-prototypes -Wdeclaration-after-statement

OBJS= fsl_shw_rand.o  fsl_shw_hash.o  fsl_shw_sym.o  fsl_shw_user.o         \
      fsl_shw_auth.o  fsl_shw_hmac.o  fsl_shw_wrap.o  um_adaptor.o  sf_util.o

CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld

#CFLAGS += -DSAHARA -DLINUX -I$(APIINCDIR)
CFLAGS += -DSAHARA -DLINUX $(INC)
CFLAGS += $(TARGET_ARCH)
# Uncomment to debug Library's creation of structures for driver
#CFLAGS +=  -DDIAG_SECURITY_FUNC
# Uncomment to simulate memory allocation errors
#CFLAGS += -DDIAG_MEM_ERRORS -DDIAG_MEM_CONST=5

LIBNAME=libsahara

ifeq ("$(TARGET_ARCH)", "")
all install:
else
all: $(LIBNAME).so $(LIBNAME).a

install: install_headers
	@mkdir -p $(DEST_DIR)/usr/lib
	cp $(LIBNAME).* $(DEST_DIR)/usr/lib

install_headers:
	@mkdir -p $(DEST_DIR)/usr/include
endif


$(LIBNAME).a: $(OBJS)
	$(AR) $@ $^

$(LIBNAME).so: $(OBJS)
	$(CC) -shared -nostartfiles -Wl,-soname,$@ -o $@ $^

.PHONY: clean
clean:
	@rm -f $(OBJS) $(LIBNAME).*

fsl_shw_rand.o: fsl_shw_rand.c $(API_INCL)

fsl_shw_hash.o: fsl_shw_hash.c $(API_INCL)

fsl_shw_sym.o: fsl_shw_sym.c $(API_INCL)

fsl_shw_user.o: fsl_shw_user.c $(API_INCL)

fsl_shw_hmac.o: fsl_shw_hmac.c $(API_INCL)

fsl_shw_auth.o: fsl_shw_auth.c $(API_INCL)

fsl_shw_wrap.o: fsl_shw_wrap.c

um_adaptor.o: um_adaptor.c

sf_util.o: sf_util.c
