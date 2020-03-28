/* Autogenerated: ./src/ExtractionOCaml/word_by_word_montgomery pasta_fp 64 '2^254 + 45560315531419706090280762371685220353' */
/* curve description: pasta_fp */
/* machine_wordsize = 64 (from "64") */
/* requested operations: (all) */
/* m = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001 (from "2^254 + 45560315531419706090280762371685220353") */
/*                                                                    */
/* NOTE: In addition to the bounds specified above each function, all */
/*   functions synthesized for this Montgomery arithmetic require the */
/*   input to be strictly less than the prime modulus (m), and also   */
/*   require the input to be in the unique saturated representation.  */
/*   All functions also ensure that these two properties are true of  */
/*   return values.                                                   */
/*  */
/* Computed values: */
/* eval z = z[0] + (z[1] << 64) + (z[2] << 128) + (z[3] << 192) */
/* bytes_eval z = z[0] + (z[1] << 8) + (z[2] << 16) + (z[3] << 24) + (z[4] << 32) + (z[5] << 40) + (z[6] << 48) + (z[7] << 56) + (z[8] << 64) + (z[9] << 72) + (z[10] << 80) + (z[11] << 88) + (z[12] << 96) + (z[13] << 104) + (z[14] << 112) + (z[15] << 120) + (z[16] << 128) + (z[17] << 136) + (z[18] << 144) + (z[19] << 152) + (z[20] << 160) + (z[21] << 168) + (z[22] << 176) + (z[23] << 184) + (z[24] << 192) + (z[25] << 200) + (z[26] << 208) + (z[27] << 216) + (z[28] << 224) + (z[29] << 232) + (z[30] << 240) + (z[31] << 248) */

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

typedef unsigned char fiat_pasta_fp_uint1;
typedef signed char fiat_pasta_fp_int1;

#if (-1 & 3) != 3
#error "This code only works on a two's complement system"
#endif

// x^{(p - 1) / 2}
const bool P_MINUS_1_OVER_2[] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
const size_t P_MINUS_1_OVER_2_LEN = 254;

/*
 * The function fiat_pasta_fp_addcarryx_u64 is an addition with carry.
 * Postconditions:
 *   out1 = (arg1 + arg2 + arg3) mod 2^64
 *   out2 = ⌊(arg1 + arg2 + arg3) / 2^64⌋
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [0x0 ~> 0xffffffffffffffff]
 *   arg3: [0x0 ~> 0xffffffffffffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0xffffffffffffffff]
 *   out2: [0x0 ~> 0x1]
 */
void fiat_pasta_fp_addcarryx_u64(uint64_t* out1, fiat_pasta_fp_uint1* out2, fiat_pasta_fp_uint1 arg1, uint64_t arg2, uint64_t arg3) {
  uint64_t tmp = arg3 + arg1;
  *out1 = arg2 + tmp;
  *out2 = (arg2 > *out1) | (arg3 > tmp);
}

/*
 * The function fiat_pasta_fp_subborrowx_u64 is a subtraction with borrow.
 * Postconditions:
 *   out1 = (-arg1 + arg2 + -arg3) mod 2^64
 *   out2 = -⌊(-arg1 + arg2 + -arg3) / 2^64⌋
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [0x0 ~> 0xffffffffffffffff]
 *   arg3: [0x0 ~> 0xffffffffffffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0xffffffffffffffff]
 *   out2: [0x0 ~> 0x1]
 */
void fiat_pasta_fp_subborrowx_u64(uint64_t* out1, fiat_pasta_fp_uint1* out2, fiat_pasta_fp_uint1 arg1, uint64_t arg2, uint64_t arg3) {
  uint64_t tmp = arg3 + arg1;
  *out1 = arg2 - tmp;
  *out2 = (arg2 < *out1) | (arg3 > tmp);
}

/*
 * The function fiat_pasta_fp_mulx_u64 is a multiplication, returning the full double-width result.
 * Postconditions:
 *   out1 = (arg1 * arg2) mod 2^64
 *   out2 = ⌊arg1 * arg2 / 2^64⌋
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0xffffffffffffffff]
 *   arg2: [0x0 ~> 0xffffffffffffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0xffffffffffffffff]
 *   out2: [0x0 ~> 0xffffffffffffffff]
 */
void fiat_pasta_fp_mulx_u64(uint64_t* out1, uint64_t* out2, uint64_t a, uint64_t b) {
  uint64_t    a_lo = (uint32_t)a;
  uint64_t    a_hi = a >> 32;
  uint64_t    b_lo = (uint32_t)b;
  uint64_t    b_hi = b >> 32;

  uint64_t    a_x_b_hi =  a_hi * b_hi;
  uint64_t    a_x_b_mid = a_hi * b_lo;
  uint64_t    b_x_a_mid = b_hi * a_lo;
  uint64_t    a_x_b_lo =  a_lo * b_lo;

  uint64_t    carry_bit = ((uint64_t)(uint32_t)a_x_b_mid +
                          (uint64_t)(uint32_t)b_x_a_mid +
                          (a_x_b_lo >> 32) ) >> 32;

  uint64_t    multhi = a_x_b_hi +
                      (a_x_b_mid >> 32) + (b_x_a_mid >> 32) +
                      carry_bit;

  *out2 = multhi;
  // TODO: This multiplication could be avoided.
  *out1 = a * b;
}

/*
 * The function fiat_pasta_fp_cmovznz_u64 is a single-word conditional move.
 * Postconditions:
 *   out1 = (if arg1 = 0 then arg2 else arg3)
 *
 * Input Bounds:
 *   arg1: [0x0 ~> 0x1]
 *   arg2: [0x0 ~> 0xffffffffffffffff]
 *   arg3: [0x0 ~> 0xffffffffffffffff]
 * Output Bounds:
 *   out1: [0x0 ~> 0xffffffffffffffff]
 */
void fiat_pasta_fp_cmovznz_u64(uint64_t* out1, fiat_pasta_fp_uint1 arg1, uint64_t arg2, uint64_t arg3) {
  fiat_pasta_fp_uint1 x1;
  uint64_t x2;
  uint64_t x3;
  x1 = (!(!arg1));
  x2 = ((fiat_pasta_fp_int1)(0x0 - x1) & UINT64_C(0xffffffffffffffff));
  x3 = ((x2 & arg3) | ((~x2) & arg2));
  *out1 = x3;
}

/*
 * The function fiat_pasta_fp_mul multiplies two field elements in the Montgomery domain.
 * Preconditions:
 *   0 ≤ eval arg1 < m
 *   0 ≤ eval arg2 < m
 * Postconditions:
 *   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) * eval (from_montgomery arg2)) mod m
 *   0 ≤ eval out1 < m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 *   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 * Output Bounds:
 *   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 */
void fiat_pasta_fp_mul(uint64_t out1[4], const uint64_t arg1[4], const uint64_t arg2[4]) {
  uint64_t x1;
  uint64_t x2;
  uint64_t x3;
  uint64_t x4;
  uint64_t x5;
  uint64_t x6;
  uint64_t x7;
  uint64_t x8;
  uint64_t x9;
  uint64_t x10;
  uint64_t x11;
  uint64_t x12;
  uint64_t x13;
  fiat_pasta_fp_uint1 x14;
  uint64_t x15;
  fiat_pasta_fp_uint1 x16;
  uint64_t x17;
  fiat_pasta_fp_uint1 x18;
  uint64_t x19;
  uint64_t x20;
  uint64_t x21;
  uint64_t x22;
  uint64_t x23;
  uint64_t x24;
  uint64_t x25;
  uint64_t x26;
  uint64_t x27;
  uint64_t x28;
  fiat_pasta_fp_uint1 x29;
  uint64_t x30;
  uint64_t x31;
  fiat_pasta_fp_uint1 x32;
  uint64_t x33;
  fiat_pasta_fp_uint1 x34;
  uint64_t x35;
  fiat_pasta_fp_uint1 x36;
  uint64_t x37;
  fiat_pasta_fp_uint1 x38;
  uint64_t x39;
  fiat_pasta_fp_uint1 x40;
  uint64_t x41;
  uint64_t x42;
  uint64_t x43;
  uint64_t x44;
  uint64_t x45;
  uint64_t x46;
  uint64_t x47;
  uint64_t x48;
  uint64_t x49;
  fiat_pasta_fp_uint1 x50;
  uint64_t x51;
  fiat_pasta_fp_uint1 x52;
  uint64_t x53;
  fiat_pasta_fp_uint1 x54;
  uint64_t x55;
  uint64_t x56;
  fiat_pasta_fp_uint1 x57;
  uint64_t x58;
  fiat_pasta_fp_uint1 x59;
  uint64_t x60;
  fiat_pasta_fp_uint1 x61;
  uint64_t x62;
  fiat_pasta_fp_uint1 x63;
  uint64_t x64;
  fiat_pasta_fp_uint1 x65;
  uint64_t x66;
  uint64_t x67;
  uint64_t x68;
  uint64_t x69;
  uint64_t x70;
  uint64_t x71;
  uint64_t x72;
  uint64_t x73;
  uint64_t x74;
  fiat_pasta_fp_uint1 x75;
  uint64_t x76;
  uint64_t x77;
  fiat_pasta_fp_uint1 x78;
  uint64_t x79;
  fiat_pasta_fp_uint1 x80;
  uint64_t x81;
  fiat_pasta_fp_uint1 x82;
  uint64_t x83;
  fiat_pasta_fp_uint1 x84;
  uint64_t x85;
  fiat_pasta_fp_uint1 x86;
  uint64_t x87;
  uint64_t x88;
  uint64_t x89;
  uint64_t x90;
  uint64_t x91;
  uint64_t x92;
  uint64_t x93;
  uint64_t x94;
  uint64_t x95;
  uint64_t x96;
  fiat_pasta_fp_uint1 x97;
  uint64_t x98;
  fiat_pasta_fp_uint1 x99;
  uint64_t x100;
