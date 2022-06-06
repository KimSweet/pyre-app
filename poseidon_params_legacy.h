#pragma once

#include "crypto.h"

//
// Legacy Poseidon hash function parameters
//

#define ROUND_COUNT_LEGACY  64
#define SPONGE_WIDTH_LEGACY 3
#define SPONGE_RATE_LEGACY  2
#define SBOX_ALPHA_LEGACY   5

// Round constants
static const Field round_keys_legacy[ROUND_COUNT_LEGACY][SPONGE_WIDTH_LEGACY] =
{
    {
        {0xd2425a07cfec91d, 0x6130240fd42af5be, 0x3fb56f00f649325, 0x107d26d6fefb125f},
        {0x1dcedf2d0ebcb628, 0x2381dfa5face2460, 0x24e92a6d36d75404, 0xce8a325b8f74c91},
        {0x5df2ca