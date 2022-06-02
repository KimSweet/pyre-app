
/*******************************************************************************
 * Poseidon is used to hash to a field in the schnorr signature scheme we use.
 * In order to be efficiently computed within the snark, it is computed using
 * the base field of the elliptic curve, and the result is then used as a
 * scalar field element, to scale the elliptic curve point. We do all of the
 * computation in this file in the base field, but output the result as a scalar.
 ********************************************************************************/

#include <assert.h>

#include "crypto.h"
#include "pasta_fp.h"
#include "pasta_fq.h"
#include "poseidon.h"
#include "poseidon_params_legacy.h"
#include "poseidon_params_kimchi.h"

#define SPONGE_BYTES(sponge_width) (sizeof(Field)*sponge_width)
#define ROUND_KEY(ctx, round, idx) *(Field *)(ctx->round_keys + (round*ctx->sponge_width + idx)*LIMBS_PER_FIELD)
#define MATRIX_ELT(m, row, col, width) *(Field *)(m + (row*width + col)*LIMBS_PER_FIELD)

static void matrix_mul(State s1, const Field **m, const size_t width)
{
    Field tmp;

    State s2;
    bzero(s2, sizeof(s2));
    for (size_t row = 0; row < width; row++) {
        // Inner product
        for (size_t col = 0; col < width; col++) {
            Field t0;
            field_mul(t0, s1[col], MATRIX_ELT(m, row, col, width));
            field_copy(tmp, s2[row]);
            field_add(s2[row], tmp, t0);
        }
    }

    for (size_t col = 0; col < width; col++) {
        field_copy(s1[col], s2[col]);
    }
}

// Legacy poseidon permutation function
static void permutation_legacy(PoseidonCtx *ctx)
{
    Field tmp;

    // Full rounds only
    for (size_t r = 0; r < ctx->full_rounds; r++) {
        // ark
        for (size_t i = 0; i < ctx->sponge_width; i++) {
            field_copy(tmp, ctx->state[i]);
            field_add(ctx->state[i], tmp, ROUND_KEY(ctx, r, i));
        }

        // sbox
        for (size_t i = 0; i < ctx->sponge_width; i++) {
            field_copy(tmp, ctx->state[i]);
            field_pow(ctx->state[i], tmp, ctx->sbox_alpha);
        }

        // mds
        matrix_mul(ctx->state, ctx->mds_matrix, ctx->sponge_width);
    }

    // Final ark
    for (size_t i = 0; i < ctx->sponge_width; i++) {
        field_copy(tmp, ctx->state[i]);
        field_add(ctx->state[i], tmp, ROUND_KEY(ctx, ctx->full_rounds, i));
    }
}

// Kimchi poseidon permutation function
static void permutation_kimchi(PoseidonCtx *ctx)
{
    Field tmp;

    // Full rounds only
    for (size_t r = 0; r < ctx->full_rounds; r++) {
        // sbox
        for (unsigned int i = 0; i < ctx->sponge_width; i++) {
            field_copy(tmp, ctx->state[i]);
            field_pow(ctx->state[i], tmp, ctx->sbox_alpha);
        }

        // mds
        matrix_mul(ctx->state, ctx->mds_matrix, ctx->sponge_width);