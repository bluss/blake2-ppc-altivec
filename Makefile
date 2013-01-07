

CFLAGS = -O3 -std=c99 -Wall -Wextra -pedantic
CFLAGS += -save-temps -fverbose-asm

ARCH = $(shell arch)
ifeq ($(ARCH),ppc)
CFLAGS += -maltivec -mabi=altivec -mcpu=7450
endif
ifeq ($(ARCH),ppc64)
CFLAGS += -maltivec -mabi=altivec
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

