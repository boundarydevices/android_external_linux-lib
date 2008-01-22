# +FHDR-----------------------------------------------------------------------
# Copyright (c) 2005, Freescale Semiconductor, Inc.
# ----------------------------------------------------------------------------
# FILE NAME      : $RCSfile: Makefile,v $
# DEPARTMENT     : Security Technology Center (STC), NCSG
# ----------------------------------------------------------------------------
# KEYWORDS : SHW, crypto, sahara
# ----------------------------------------------------------------------------
# PURPOSE: Makefile for API Library for RNGA 
# -FHDR-----------------------------------------------------------------------

AR = ar -crv
RM = rm -f
CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld


INC := $(INCLUDE)

# Add compilation checks
CFLAGS += -g -Wall -W -Wmissing-prototypes -Wstrict-prototypes -Wdeclaration-after-statement
CFLAGS +=  -DFSL_PLATFORM_OTHER -DFSL_HAVE_RNGA $(INC)


OBJS= fsl_shw_rand.o  fsl_shw_hash.o  fsl_shw_sym.o  fsl_shw_user.o         \
      fsl_shw_auth.o  fsl_shw_hmac.o  fsl_shw_wrap.o  

LIBNAME=libfsl_shw


all: $(LIBNAME).so $(LIBNAME).a 

install: install_headers
	@mkdir -p $(DEST_DIR)/usr/lib
	cp $(LIBNAME).* $(DEST_DIR)/usr/lib

install_headers:
	@mkdir -p $(DEST_DIR)/usr/include

$(LIBNAME).a: $(OBJS)
	$(AR) $@ $^

$(LIBNAME).so: $(OBJS)
	$(CC) -shared -nostartfiles -Wl,-soname,$@ -o $@ $^

.PHONY: clean
clean:
	@rm -f *.o $(LIBNAME).*
