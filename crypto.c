// Mina schnorr signatures and eliptic curve arithmatic
//
//     * Produces a schnorr signature according to the specification here:
//       https://github.com/MinaProtocol/mina/blob/develop/docs/specs/signatures/description.md
//
//     * Signer reference here: https://github.com/MinaProtocol/signer-reference
//
//     * Curve arithmatic
//         - field_add, field_sub, field_mul, field_sq, field_inv, field_negate, field_pow, field_eq
//         - scalar_add, scalar_sub, scalar_mul, scalar_sq, scalar_pow, scalar_eq
//         - group_add, group_dbl, group_scalar_mul (group elements use projective coordinates)
//         - affine_scalar_mul
//         - affine_from_group
//         - generate_pubkey, generate_keypair
//         - sign
//
//     * Curve details
//         Pasta.Pallas (https://github.com/zcash/pasta)
//         E1/Fp : y^2 = x^3 + 5
//         GROUP_ORDER   = 28948022309329048855892746252171976963363056481941647379679742748393362948097 (Fq, 0x94)
//         FIELD_MODULUS = 28948022309329048855892746252171976963363056481941560715954676764349967630337 (Fp, 0x4c)

// #include <assert.h>

#define THROW exit

#include <assert.h>
#include <inttypes.h>
#include <math.h>

#include "crypto.h"
#include "utils.h"
#include "poseidon.h"
#include "pasta_fp.h"
#include "pasta_fq.h"
#include "blake2.h"
#include "libbase58.h"
#include "sha256.h"

// a = 0, b = 5
static const Field GROUP_COEFF_B = {
  0xa1a55e68ffffffed, 0x74c2a54b4f4982f3, 0xfffffffffffffffd, 0x3fffffffffffffff
};

static const Field FIELD_ONE = {
  0x34786d38fffffffd, 0x992c350be41914ad, 0xffffffffffffffff, 0x3fffffffffffffff
};
static const Field FIELD_THREE = {
  0x6b0ee5d0fffffff5, 0x86f76d2b99b14bd0, 0xfffffffffffffffe, 0x3fffffffffffffff
};
static const Field FIELD_FOUR = {
  0x65a221cfffffff1, 0xfddd093b747d6762, 0xfffffffffffffffd, 0x3fffffffffffffff
};
static const Field FIELD_EIGHT = {
  0x7387134cffffffe1, 0xd973797adfadd5a8, 0xfffffffffffffffb, 0x3fffffffffffffff
};
static const Field FIELD_ZERO = { 0, 0, 0, 0 };
static const Scalar SCALAR_ZERO = { 0, 0, 0, 0 };

// (X : Y : Z) = (0 : 1 : 0)
static const Group GROUP_ZERO = {
    { 0, 0, 0, 0},
    { 0x34786d38fffffffd, 0x992c350be41914ad, 0xffffffffffffffff, 0x3fffffffffffffff },
    { 0, 0, 0, 0}
};

// g_generator = (1 : 12418654782883325593414442427049395787963493412651469444558597405572177144507)
static const Affine AFFINE_ONE = {
    {
        0x34786d38fffffffd, 0x992c350be41914ad, 0xffffffffffffffff, 0x3fffffffffffffff
    },
    {
        0x2f474795455d409d, 0xb443b9b74b8255d9, 0x270c412f2c9a5d66, 0x8e00f71ba43dd6b
    }
};

bool field_from_hex(Field b, const char *hex) {
  if (strnlen(hex, 64) != 64) {
    return false;
  }
  uint8_t bytes[32];
  for (size_t i = 0; i < sizeof(bytes); i++) {
    sscanf(&hex[2*i], "%02hhx", &bytes[i]);
  }

  if (bytes[31] & 0xc0) {
      return false;
  }

  fiat_pasta_fp_to_montgomery(b, (uint64_t *)bytes);
  return true;
}

void field_copy(Field c, const Field a)
{
    fiat_pasta_fp_copy(c, a);
}

bool field_is_odd(const Field y)
{
    uint64_t tmp[4];
    fiat_pasta_fp_from_montgomery(tmp, y);
    return tmp[0] & 1;
}

void field_add(Field c, const Field a, const Field b)
{
    fiat_pasta_fp_add(c, a, b);
}

void field_sub(Field c, const Field a, const Field b)
{
    fiat_pasta_fp_sub(c, a, b)