/* Autogenerated: ./src/ExtractionOCaml/word_by_word_montgomery pasta_fq 64 '2^254 + 45560315531506369815346746415080538113' */
/* curve description: pasta_fq */
/* machine_wordsize = 64 (from "64") */
/* requested operations: (all) */
/* m = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001 (from "2^254 + 45560315531506369815346746415080538113") */
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
typedef unsigned char fiat_pasta_fq_uint1;
typedef signed char fiat_pasta_fq_int1;

#if (-1 & 3) != 3
#error "This code only works on a two's complement system"
#endif


/*
 * The function fiat_pasta_fq_addcarryx_u64 is an addi