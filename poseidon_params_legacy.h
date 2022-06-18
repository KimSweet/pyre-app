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
        {0x5df2ca8d054dc3a, 0x7fb9bf2f82379968, 0x424e2934a76cffb8, 0xb775aeab9b31f6a}
    },
    {
        {0x9e6d7a567eaacc30, 0xced5d7ac222f233c, 0x2fe5c196ec8ffd26, 0x2a8f0caeda769601},
        {0xdc68662e69f84551, 0x1495455fbfab4087, 0xab2e97a03e2a079d, 0x3e93afa4e82ac2a0},
        {0x4cc46cd35daca246, 0x54dcc54ee433c73f, 0x893be89025513bde, 0x3b52fbe29b9d1b53}
    },
    {
        {0xd96382010ec8b913, 0x9921d471216af4b5, 0xa7df09d5ecf06de, 0xa360d0e19232e76},
        {0x408add78a89dcf34, 0xb15031ad7e3ec92, 0x8ef35f1ab8093a79, 0x23276aa7a64b85a4},
        {0xdac52436f6c1cdd0, 0x46257295a42ee0b2, 