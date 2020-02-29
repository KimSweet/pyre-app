
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#define INVALID_PARAMETER 1

#define BIP32_PATH_LEN 5
#define BIP32_HARDENED_OFFSET 0x80000000

#define FIELD_BYTES  32
#define SCALAR_BYTES 32

#define LIMBS_PER_FIELD 4
#define LIMBS_PER_SCALAR 4

#define FIELD_SIZE_IN_BITS 255

#define MINA_ADDRESS_LEN 56 // includes null-byte

#define COIN 1000000000ULL

typedef uint64_t Field[LIMBS_PER_FIELD];
typedef uint64_t Scalar[LIMBS_PER_FIELD];

typedef uint64_t Currency;
#define FEE_BITS 64
#define AMOUNT_BITS 64
typedef uint32_t GlobalSlot;
#define GLOBAL_SLOT_BITS 32
typedef uint32_t Nonce;
#define NONCE_BITS 32
typedef uint64_t TokenId;
#define TOKEN_ID_BITS 64