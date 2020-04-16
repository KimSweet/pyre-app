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
  fiat_pasta_fp_uint1 x101;
  uint64_t x102;
  uint64_t x103;
  fiat_pasta_fp_uint1 x104;
  uint64_t x105;
  fiat_pasta_fp_uint1 x106;
  uint64_t x107;
  fiat_pasta_fp_uint1 x108;
  uint64_t x109;
  fiat_pasta_fp_uint1 x110;
  uint64_t x111;
  fiat_pasta_fp_uint1 x112;
  uint64_t x113;
  uint64_t x114;
  uint64_t x115;
  uint64_t x116;
  uint64_t x117;
  uint64_t x118;
  uint64_t x119;
  uint64_t x120;
  uint64_t x121;
  fiat_pasta_fp_uint1 x122;
  uint64_t x123;
  uint64_t x124;
  fiat_pasta_fp_uint1 x125;
  uint64_t x126;
  fiat_pasta_fp_uint1 x127;
  uint64_t x128;
  fiat_pasta_fp_uint1 x129;
  uint64_t x130;
  fiat_pasta_fp_uint1 x131;
  uint64_t x132;
  fiat_pasta_fp_uint1 x133;
  uint64_t x134;
  uint64_t x135;
  uint64_t x136;
  uint64_t x137;
  uint64_t x138;
  uint64_t x139;
  uint64_t x140;
  uint64_t x141;
  uint64_t x142;
  uint64_t x143;
  fiat_pasta_fp_uint1 x144;
  uint64_t x145;
  fiat_pasta_fp_uint1 x146;
  uint64_t x147;
  fiat_pasta_fp_uint1 x148;
  uint64_t x149;
  uint64_t x150;
  fiat_pasta_fp_uint1 x151;
  uint64_t x152;
  fiat_pasta_fp_uint1 x153;
  uint64_t x154;
  fiat_pasta_fp_uint1 x155;
  uint64_t x156;
  fiat_pasta_fp_uint1 x157;
  uint64_t x158;
  fiat_pasta_fp_uint1 x159;
  uint64_t x160;
  uint64_t x161;
  uint64_t x162;
  uint64_t x163;
  uint64_t x164;
  uint64_t x165;
  uint64_t x166;
  uint64_t x167;
  uint64_t x168;
  fiat_pasta_fp_uint1 x169;
  uint64_t x170;
  uint64_t x171;
  fiat_pasta_fp_uint1 x172;
  uint64_t x173;
  fiat_pasta_fp_uint1 x174;
  uint64_t x175;
  fiat_pasta_fp_uint1 x176;
  uint64_t x177;
  fiat_pasta_fp_uint1 x178;
  uint64_t x179;
  fiat_pasta_fp_uint1 x180;
  uint64_t x181;
  uint64_t x182;
  fiat_pasta_fp_uint1 x183;
  uint64_t x184;
  fiat_pasta_fp_uint1 x185;
  uint64_t x186;
  fiat_pasta_fp_uint1 x187;
  uint64_t x188;
  fiat_pasta_fp_uint1 x189;
  uint64_t x190;
  fiat_pasta_fp_uint1 x191;
  uint64_t x192;
  uint64_t x193;
  uint64_t x194;
  uint64_t x195;
  x1 = (arg1[1]);
  x2 = (arg1[2]);
  x3 = (arg1[3]);
  x4 = (arg1[0]);
  fiat_pasta_fp_mulx_u64(&x5, &x6, x4, (arg2[3]));
  fiat_pasta_fp_mulx_u64(&x7, &x8, x4, (arg2[2]));
  fiat_pasta_fp_mulx_u64(&x9, &x10, x4, (arg2[1]));
  fiat_pasta_fp_mulx_u64(&x11, &x12, x4, (arg2[0]));
  fiat_pasta_fp_addcarryx_u64(&x13, &x14, 0x0, x12, x9);
  fiat_pasta_fp_addcarryx_u64(&x15, &x16, x14, x10, x7);
  fiat_pasta_fp_addcarryx_u64(&x17, &x18, x16, x8, x5);
  x19 = (x18 + x6);
  fiat_pasta_fp_mulx_u64(&x20, &x21, x11, UINT64_C(0x992d30ecffffffff));
  fiat_pasta_fp_mulx_u64(&x22, &x23, x20, UINT64_C(0x4000000000000000));
  fiat_pasta_fp_mulx_u64(&x24, &x25, x20, UINT64_C(0x224698fc094cf91b));
  fiat_pasta_fp_mulx_u64(&x26, &x27, x20, UINT64_C(0x992d30ed00000001));
  fiat_pasta_fp_addcarryx_u64(&x28, &x29, 0x0, x27, x24);
  x30 = (x29 + x25);
  fiat_pasta_fp_addcarryx_u64(&x31, &x32, 0x0, x11, x26);
  fiat_pasta_fp_addcarryx_u64(&x33, &x34, x32, x13, x28);
  fiat_pasta_fp_addcarryx_u64(&x35, &x36, x34, x15, x30);
  fiat_pasta_fp_addcarryx_u64(&x37, &x38, x36, x17, x22);
  fiat_pasta_fp_addcarryx_u64(&x39, &x40, x38, x19, x23);
  fiat_pasta_fp_mulx_u64(&x41, &x42, x1, (arg2[3]));
  fiat_pasta_fp_mulx_u64(&x43, &x44, x1, (arg2[2]));
  fiat_pasta_fp_mulx_u64(&x45, &x46, x1, (arg2[1]));
  fiat_pasta_fp_mulx_u64(&x47, &x48, x1, (arg2[0]));
  fiat_pasta_fp_addcarryx_u64(&x49, &x50, 0x0, x48, x45);
  fiat_pasta_fp_addcarryx_u64(&x51, &x52, x50, x46, x43);
  fiat_pasta_fp_addcarryx_u64(&x53, &x54, x52, x44, x41);
  x55 = (x54 + x42);
  fiat_pasta_fp_addcarryx_u64(&x56, &x57, 0x0, x33, x47);
  fiat_pasta_fp_addcarryx_u64(&x58, &x59, x57, x35, x49);
  fiat_pasta_fp_addcarryx_u64(&x60, &x61, x59, x37, x51);
  fiat_pasta_fp_addcarryx_u64(&x62, &x63, x61, x39, x53);
  fiat_pasta_fp_addcarryx_u64(&x64, &x65, x63, x40, x55);
  fiat_pasta_fp_mulx_u64(&x66, &x67, x56, UINT64_C(0x992d30ecffffffff));
  fiat_pasta_fp_mulx_u64(&x68, &x69, x66, UINT64_C(0x4000000000000000));
  fiat_pasta_fp_mulx_u64(&x70, &x71, x66, UINT64_C(0x224698fc094cf91b));
  fiat_pasta_fp_mulx_u64(&x72, &x73, x66, UINT64_C(0x992d30ed00000001));
  fiat_pasta_fp_addcarryx_u64(&x74, &x75, 0x0, x73, x70);
  x76 = (x75 + x71);
  fiat_pasta_fp_addcarryx_u64(&x77, &x78, 0x0, x56, x72);
  fiat_pasta_fp_addcarryx_u64(&x79, &x80, x78, x58, x74);
  fiat_pasta_fp_addcarryx_u64(&x81, &x82, x80, x60, x76);
  fiat_pasta_fp_addcarryx_u64(&x83, &x84, x82, x62, x68);
  fiat_pasta_fp_addcarryx_u64(&x85, &x86, x84, x64, x69);
  x87 = ((uint64_t)x86 + x65);
  fiat_pasta_fp_mulx_u64(&x88, &x89, x2, (arg2[3]));
  fiat_pasta_fp_mulx_u64(&x90, &x91, x2, (arg2[2]));
  fiat_pasta_fp_mulx_u64(&x92, &x93, x2, (arg2[1]));
  fiat_pasta_fp_mulx_u64(&x94, &x95, x2, (arg2[0]));
  fiat_pasta_fp_addcarryx_u64(&x96, &x97, 0x0, x95, x92);
  fiat_pasta_fp_addcarryx_u64(&x98, &x99, x97, x93, x90);
  fiat_pasta_fp_addcarryx_u64(&x100, &x101, x99, x91, x88);
  x102 = (x101 + x89);
  fiat_pasta_fp_addcarryx_u64(&x103, &x104, 0x0, x79, x94);
  fiat_pasta_fp_addcarryx_u64(&x105, &x106, x104, x81, x96);
  fiat_pasta_fp_addcarryx_u64(&x107, &x108, x106, x83, x98);
  fiat_pasta_fp_addcarryx_u64(&x109, &x110, x108, x85, x100);
  fiat_pasta_fp_addcarryx_u64(&x111, &x112, x110, x87, x102);
  fiat_pasta_fp_mulx_u64(&x113, &x114, x103, UINT64_C(0x992d30ecffffffff));
  fiat_pasta_fp_mulx_u64(&x115, &x116, x113, UINT64_C(0x4000000000000000));
  fiat_pasta_fp_mulx_u64(&x117, &x118, x113, UINT64_C(0x224698fc094cf91b));
  fiat_pasta_fp_mulx_u64(&x119, &x120, x113, UINT64_C(0x992d30ed00000001));
  fiat_pasta_fp_addcarryx_u64(&x121, &x122, 0x0, x120, x117);
  x123 = (x122 + x118);
  fiat_pasta_fp_addcarryx_u64(&x124, &x125, 0x0, x103, x119);
  fiat_pasta_fp_addcarryx_u64(&x126, &x127, x125, x105, x121);
  fiat_pasta_fp_addcarryx_u64(&x128, &x129, x127, x107, x123);
  fiat_pasta_fp_addcarryx_u64(&x130, &x131, x129, x109, x115);
  fiat_pasta_fp_addcarryx_u64(&x132, &x133, x131, x111, x116);
  x134 = ((uint64_t)x133 + x112);
  fiat_pasta_fp_mulx_u64(&x135, &x136, x3, (arg2[3]));
  fiat_pasta_fp_mulx_u64(&x137, &x138, x3, (arg2[2]));
  fiat_pasta_fp_mulx_u64(&x139, &x140, x3, (arg2[1]));
  fiat_pasta_fp_mulx_u64(&x141, &x142, x3, (arg2[0]));
  fiat_pasta_fp_addcarryx_u64(&x143, &x144, 0x0, x142, x139);
  fiat_pasta_fp_addcarryx_u64(&x145, &x146, x144, x140, x