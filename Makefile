ifneq ($(shell uname -s),"Darwin")
CFLAGS=-D OSX
endif

all: reference_signer unit_tests

OBJS = base10.o \
	base58.o \
	blake2b-ref.o \
	sha256.o \
	crypto.o \
	pasta_fp.o \
	pasta_fq.o \
	poseidon.o \
	utils.o \
	curve_checks.o

reference_signer: $(OBJS) reference_signer.c
	$(CC) $(CFLAGS) -Wall -Werror $@.c -o $@ $(OBJS) -l