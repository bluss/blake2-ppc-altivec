

CFLAGS = -O3 -g -std=c99 -Wall -Wextra -pedantic
CFLAGS += -save-temps -fverbose-asm

KERN = $(shell uname -s)
ARCH = $(shell arch)

ifneq ($(findstring ppc,$(ARCH)),)
CFLAGS += -maltivec -mabi=altivec

ifeq ($(ARCH),ppc)
CFLAGS += -mcpu=7450
endif
ifeq ($(KERN),Linux)
CFLAGS += -mno-vrsave
endif

endif

blake2s: blake2s.o blake2s-generic.o

blake2s-altivec: blake2s.o blake2s-altivec.o

clean:
	rm -f *.o

.PHONY: clean


# use gcc 4.7 if we can
ifneq ($(shell which gcc-4.7),)
CC = gcc-4.7
endif

