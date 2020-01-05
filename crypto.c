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
    fiat_pasta_fp_sub(c, a, b);
}

void field_mul(Field c, const Field a, const Field b)
{
    fiat_pasta_fp_mul(c, a, b);
}

void field_sq(Field c, const Field a)
{
    fiat_pasta_fp_square(c, a);
}

void field_pow(Field c, const Field a, const uint8_t b)
{
    field_copy(c, FIELD_ONE);

    if (b == 0) {
      return;
    }

    Field tmp;
    for (size_t i = log2(b) + 1; i > 0; i--) {
        field_copy(tmp, c);
        field_sq(c, tmp);

        if (b & (1 << (i - 1))) {
            field_copy(tmp, c);
            field_mul(c, tmp, a);
        }
    }
}

void field_inv(Field c, const Field a)
{
    fiat_pasta_fp_inv(c, a);
}

void field_negate(Field c, const Field a)
{
    fiat_pasta_fp_opp(c, a);
}

unsigned int field_eq(const Field a, const Field b)
{
    if (fiat_pasta_fp_equals(a, b)) {
      return 1;
    } else {
      return 0;
    }
}

bool scalar_from_hex(Field b, const char *hex) {
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

  fiat_pasta_fq_to_montgomery(b, (uint64_t *)bytes);
  return true;
}

void scalar_from_words(Scalar b, const uint64_t words[4])
{
    uint64_t tmp[4];
    memcpy(tmp, words, sizeof(tmp));
    tmp[3] &= (((uint64_t)1 << 62) - 1); // drop top two bits
    fiat_pasta_fq_to_montgomery(b, tmp);
}

void scalar_copy(Scalar b, const Scalar a)
{
    fiat_pasta_fq_copy(b, a);
}

void scalar_add(Scalar c, const Scalar a, const Scalar b)
{
    fiat_pasta_fq_add(c, a, b);
}

void scalar_sub(Scalar c, const Scalar a, const Scalar b)
{
    fiat_pasta_fq_sub(c, a, b);
}

void scalar_mul(Scalar c, const Scalar a, const Scalar b)
{
    fiat_pasta_fq_mul(c, a, b);
}

void scalar_sq(Scalar c, const Scalar a)
{
    fiat_pasta_fq_square(c, a);
}

void scalar_negate(Scalar c, const Scalar a)
{
    fiat_pasta_fq_opp(c, a);
}

bool scalar_eq(const Scalar a, const Scalar b)
{
    return fiat_pasta_fq_equals(a, b);
}

// zero is the only point with Z = 0 in jacobian coordinates
unsigned int is_zero(const Group *p)
{
    return field_eq(p->Z, FIELD_ZERO);
}

unsigned int affine_is_zero(const Affine *p)
{
    return (field_eq(p->x, FIELD_ZERO) && field_eq(p->y, FIELD_ZERO));
}

unsigned int group_is_on_curve(const Group *p)
{
    if (is_zero(p)) {
        return 1;
    }

    Field lhs, rhs;
    if (field_eq(p->Z, FIELD_ONE)) {
        // we can check y^2 == x^3 + ax + b
        field_sq(lhs, p->Y);                // y^2
        field_sq(rhs, p->X);                // x^2
        field_mul(rhs, rhs, p->X);          // x^3
        field_add(rhs, rhs, GROUP_COEFF_B); // x^3 + b
    }
    else {
        // we check (y/z^3)^2 == (x/z^2)^3 + b
        // => y^2 == x^3 + bz^6
        Field x3, z6;
        field_sq(x3, p->X);                 // x^2
        field_mul(x3, x3, p->X);            // x^3
        field_sq(lhs, p->Y);                // y^2
        field_sq(z6, p->Z);                 // z^2
        field_sq(z6, z6);                   // z^4
        field_mul(z6, z6, p->Z);            // z^5
        field_mul(z6, z6, p->Z);            // z^6

        field_mul(rhs, z6, GROUP_COEFF_B);  // bz^6
        field_add(rhs, x3, rhs);            // x^3 + bz^6
    }

    return field_eq(lhs, rhs);
}

void affine_to_group(Group *r, const Affine *p)
{
    if (field_eq(p->x, FIELD_ZERO) && field_eq(p->y, FIELD_ZERO)) {
        memcpy(r->X, FIELD_ZERO, FIELD_BYTES);
        memcpy(r->Y, FIELD_ONE, FIELD_BYTES);
        memcpy(r->Z, FIELD_ZERO, FIELD_BYTES);
        return;
    }

    memcpy(r->X, p->x, FIELD_BYTES);
    memcpy(r->Y, p->y, FIELD_BYTES);
    memcpy(r->Z, FIELD_ONE, FIELD_BYTES);
}

void affine_from_group(Affine *r, const Group *p)
{
    if (field_eq(p->Z, FIELD_ZERO)) {
        memcpy(r->x, FIELD_ZERO, FIELD_BYTES);
        memcpy(r->y, FIELD_ZERO, FIELD_BYTES);
        return;
    }

    Field zi, zi2, zi3;
    field_inv(zi, p->Z);        // 1/Z
    field_mul(zi2, zi, zi);     // 1/Z^2
    field_mul(zi3, zi2, zi);    // 1/Z^3
    field_mul(r->x, p->X, zi2); // X/Z^2
    field_mul(r->y, p->Y, zi3); // Y/Z^3
}

void group_one(Group *a)
{
    affine_to_group(a, &AFFINE_ONE);
}

// https://www.hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/doubling/dbl-2009-l.op3
// cost 2M + 5S + 6add + 3*2 + 1*3 + 1*8
void group_dbl(Group *r, const Group *p)
{
    if (is_zero(p)) {
        *r = *p;
        return;
    }

    Field a, b, c;
    field_sq(a, p->X);            // a = X1^2
    field_sq(b, p->Y);            // b = Y1^2
    field_sq(c, b);               // c = b^2

    Field d, e, f;
    field_add(r->X, p->X, b);     // t0 = X1 + b
    field_sq(r->Y, r->X);         // t1 = t0^2
    field_sub(r->Z, r->Y, a);     // t2 = t1 - a
    field_sub(r->X, r->Z, c);     // t3 = t2 - c
    field_add(d, r->X, r->X);     // d = 2 * t3
    field_mul(e, FIELD_THREE, a); // e = 3 * a
    field_sq(f, e);               // f = e^2

    field_add(r->Y, d, d);        // t4 = 2 * d
    field_sub(r->X, f, r->Y);     // X = f - t4

    field_sub(r->Y, d, r->X);     // t5 = d - X
    field_mul(f, FIELD_EIGHT, c); // t6 = 8 * c
    field_mul(r->Z, e, r->Y);     // t7 = e * t5
    field_sub(r->Y, r->Z, f);     // Y = t7 - t6

    field_mul(f, p->Y, p->Z);     // t8 = Y1 * Z1
    field_add(r->Z, f, f);        // Z = 2 * t8
}

// https://www.hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/addition/add-2007-bl.op3
// cost 11M + 5S + 9add + 4*2
void group_add(Group *r, const Group *p, const Group *q)
{
    if (is_zero(p)) {
        *r = *q;
        return;
    }

    if (is_zero(q)) {
        *r = *p;
        return;
    }

    if (field_eq(p->X, q->X) && field_eq(p->Y, q->Y) && field_eq(p->Z, q->Z)) {
        return group_dbl(r, p);
    }

    Field z1z1, z2z2;
    field_sq(z1z1, p->Z);         // Z1Z1 = Z1^2
    field_sq(z2z2, q->Z);         // Z2Z2 = Z2^2

    Field u1, u2, s1, s2;
    field_mul(u1, p->X, z2z2);    // u1 = x1 * z2z2
    field_mul(u2, q->X, z1z1);    // u2 = x2 * z1z1
    field_mul(r->X, q->Z, z2z2);  // t0 = z2 * z2z2
    field_mul(s1, p->Y, r->X);    // s1 = y1 * t0
    field_mul(r->Y, p->Z, z1z1);  // t1 = z1 * z1z1
    field_mul(s2, q->Y, r->Y);    // s2 = y2 * t1

    Field h, i, j, w, v;
    field_sub(h, u2, u1);         // h = u2 - u1
    field_add(r->Z, h, h);        // t2 = 2 * h
    field_sq(i, r->Z);            // i = t2^2
    field_mul(j, h, i);           // j = h * i
    field_sub(r->X, s2, s1);      // t3 = s2 - s1
    field_add(w, r->X, r->X);     // w = 2 * t3
    field_mul(v, u1, i);          // v = u1 * i

    // X3 = w^2 - j - 2*v
    field_sq(r->X, w);            // t4 = w^2
    field_add(r->Y, v, v);        // t5 = 2 * v
    field_sub(r->Z, r->X, j);     // t6 = t4 - j
    field_sub(r->X, r->Z, r->Y);  // t6 - t5

    // Y3 = w * (v - X3) - 2*s1*j
    field_sub(r->Y, v, r->X);     // t7 = v - X3
    field_mul(r->Z, s1, j);       // t8 = s1 * j
    field_add(s1, r->Z, r->Z);    // t9 = 2 * t8
    field_mul(r->Z, w, r->Y);     // t10 = w * t7
    field_sub(r->Y, r->Z, s1);    // w * (v - X3) - 2*s1*j

    // Z3 = ((Z1 + Z2)^2 - Z1Z1 - Z2Z2) * h
    field_add(r->Z, p->Z, q->Z);  // t11 = z1 + z2
    field_sq(s1, r->Z);           // t12 = (z1 + z2)^2
    field_sub(r->Z, s1, z1z1);    // t13 = (z1 + z2)^2 - z1z1
    field_sub(j, r->Z, z2z2);     // t14 = (z1 + z2)^2 - z1z1 - z2z2
    field_mul(r->Z, j, h);        // ((z1 + z2)^2 - z1z1 - z2z2) * h
}

// https://www.hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/addition/madd-2007-bl.op3
// for p = (X1, Y1, Z1), q = (X2, Y2, Z2); assumes Z2 = 1
// cost 7M + 4S + 9add + 3*2 + 1*4 ?
void group_madd(Group *r, const Group *p, const Group *q)
{
    if (is_zero(p)) {
        *r = *q;
        return;
    }
    if (is_zero(q)) {
        *r = *p;
        return;
    }

    Field z1z1, u2;
    field_sq(z1z1, p->Z);            // z1z1 = Z1^2
    field_mul(u2, q->X, z1z1);       // u2 = X2 * z1z1

    Field s2;
    field_mul(r->X, p->Z, z1z1);     // t0 = Z1 * z1z1
    field_mul(s2, q->Y, r->X);       // s2 = Y2 * t0

    Field h, hh;
    field_sub(h, u2, p->X);          // h = u2 - X1
    field_sq(hh, h);                 // hh = h^2

    Field j, w, v;
    field_mul(r->X, FIELD_FOUR, hh); // i = 4 * hh
    field_mul(j, h, r->X);           // j = h * i
    field_sub(r->Y, s2, p->Y);       // t1 = s2 - Y1
    field_add(w, r->Y, r->Y);        // w = 2 * t1
    field_mul(v, p->X, r->X);        // v = X1 * i

    // X3 = w^2 - J - 2*V
    field_sq(r->X, w);               // t2 = w^2
    field_add(r->Y, v, v);           // t3 = 2*v
    field_sub(r->Z, r->X, j);        // t4 = t2 - j
    field_sub(r->X, r->Z, r->Y);     // X3 = w^2 - j - 2*v = t4 - t3

    // Y3 = w * (V - X3) - 2*Y1*J
    field_sub(r->Y, v, r->X);        // t5 = v - X3
    field_mul(v, p->Y, j);           // t6 = Y1 * j
    field_add(r->Z, v, v);           // t7 = 2 * t6
    field_mul(s2, w, r->Y);          // t8 = w * t5
    field_sub(r->Y, s2, r->Z);       // w * (v - X3) - 2*Y1*j = t8 - t7

    // Z3 = (Z1 + H)^2 - Z1Z1 - HH
    field_add(w, p->Z, h);           // t9 = Z1 + h
    field_sq(v, w);                  // t10 = t9^2
    field_sub(w, v, z1z1);           // t11 = t10 - z1z1
    field_sub(r->Z, w, hh);          // (Z1 + h)^2 - Z1Z1 - hh = t11 - hh
}

void group_scalar_mul(Group *r, const Scalar k, const Group *p)
{
    *r = GROUP_ZERO;
    if (is_zero(p)) {
        return;
    }
    if (scalar_eq(k, SCALAR_ZERO)) {
        return;
    }

    // Group r1 = *p;
    Group tmp;

    uint64_t k_bits[4];
    fiat_pasta_fq_from_montgomery(k_bits, k);

    // Not constant time
    for (size_t i = 0; i < FIELD_SIZE_IN_BITS; ++i) {
        size_t j = FIELD_SIZE_IN_BITS - 1 - i;
        size_t limb_idx = j / 64;
        size_t in_limb_idx = (j % 64);
        bool di = (k_bits[limb_idx] >> in_limb_idx) & 1;

        group_dbl(&tmp, r);

        if (di) {
          group_add(r, &tmp, p);
        } else {
          field_copy(r->X, tmp.X);
          field_copy(r->Y, tmp.Y);
          field_copy(r->Z, tmp.Z);
        }
    }
}

void group_negate(Group *q, const Group *p)
{
    field_copy(q->X, p->X);
    field_negate(q->Y, p->Y);
    field_copy(q->Z, p->Z);
}

void affine_scalar_mul(Affine *r, const Scalar k, const Affine *p)
{
    Group pp, pr;
    affine_to_group(&pp, p);
    group_scalar_mul(&pr, k, &pp);
    affine_from_group(r, &pr);
}

bool affine_eq(const Affine *p, const Affine *q)
{
    return field_eq(p->x, q->x) && field_eq(p->y, q->y);
}

void affine_add(Affine *r, const Affine *p, const Affine *q)
{
    Group gr, gp, gq;
    affine_to_group(&gp, p);
    affine_to_group(&gq, q);
    group_add(&gr, &gp, &gq);
    affine_from_group(r, &gr);
}

void affine_negate(Affine *q, const Affine *p)
{
    Group gq, gp;
    affine_to_group(&gp, p);
    group_negate(&gq, &gp);
    affine_from_group(q, &gq);
}

bool affine_is_on_curve(const Affine *p)
{
    Group gp;
    affine_to_group(&gp, p);
    return group_is_on_curve(&gp);
}

void roinput_print_fields(const ROInput *input) {
  for (size_t i = 0; i < LIMBS_PER_FIELD * input->fields_len; ++i) {
    printf("fs[%zu] = 0x%" PRIx64 "\n", i, input->fields[i]);
  }
}

void roinput_print_bits(const ROInput *input) {
  for (size_t i = 0; i < input->bits_len; ++i) {
    printf("bs[%zu] = %u\n", i, packed_bit_array_get(input->bits, i));
  }
}

// input for poseidon
void roinput_add_field(ROInput *input, const Field a) {
  int remaining = (int)input->fields_capacity - (int)input->fields_len;
  if (remaining < 1) {
    printf("fields at capacity\n");
    exit(1);
  }

  size_t offset = LIMBS_PER_FIELD * input->fields_len;

  fiat_pasta_fp_copy(input->fields + offset, a);

  input->fields_len += 1;
}

void roinput_add_bit(ROInput *input, bool b) {
  int remaining = (int)input->bits_capacity - (int)input->bits_len;

  if (remaining < 1) {
    printf("add_bit: bits at capacity\n");
    exit(1);
  }

  size_t offset = input->bits_len;

  packed_bit_array_set(input->bits, offset, b);
  input->bits_len += 1;
}

void roinput_add_scalar(ROInput *input, const Scalar a) {
  int remaining = (int)input->bits_capacity - (int)input->bits_len;
  const size_t len = FIELD_SIZE_IN_BITS;

  uint64_t scalar_bigint[4];
  fiat_pasta_fq_from_montgomery(scalar_bigint, a);

  if (remaining < len) {
    printf("add_scalar: bits at capacity\n");
    exit(1);
  }

  size_t offset = input->bits_len;
  for (size_t i = 0; i < len; ++i) {
    size_t limb_idx = i / 64;
    size_t in_limb_idx = (i % 64);
    bool b = (scalar_bigint[limb_idx] >> in_limb_idx) & 1;
    packed_bit_array_set(input->bits, offset + i, b);
  }

  input->bits_len += len;
}

void roinput_add_bytes(ROInput *input, const uint8_t *bytes, size_t len) {
  int remaining = (i