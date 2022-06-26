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
        {0xdac52436f6c1cdd0, 0x46257295a42ee0b2, 0x3090799e349ade62, 0x261f8de11adb9313}
    },
    {
        {0x51fb0207578466ed, 0xace76bd4ce53012a, 0x45f74735a873a7a6, 0x25be1a7e5c85f326},
        {0xdee055cc9572cc61, 0x9373df1526d6e34b, 0x2084c5641a3122a3, 0x3062d3265012feed},
        {0x1bd9070c51f40e9b, 0x9ea653d50b3fa6f, 0xa31a6b51060fc899, 0x703ce3434f96fea}
    },
    {
        {0x937e0bd5442efc15, 0xc1b3a953fbd209b7, 0xb3737616f1f7eb8b, 0x5b10777bdf5dacd},
        {0x10791e59a7d5788a, 0x12f9041014d93ea, 0xb4bc24f34f470c71, 0x2f00cd1954db2d8c},
        {0xe912d7ae74abca54, 0xc5c26a35e725fd41, 0xb6af66a891d1c628, 0x3e5ec2bf0970d4a3}
    },
    {
        {0x8340c5579ef76e75, 0x84685beb75f0fd3d, 0xd3a06c47523190d2, 0x308b8895c2d04040},
        {0x457356859f821f53, 0x8abdeeacf3a1ba9e, 0x43b602e5b2ad8b28, 0xc1879b3610fd2f4},
  