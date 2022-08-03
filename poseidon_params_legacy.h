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
        {0x97b86a707b5809bc, 0x8dd94d73fb34a3ee, 0x5141652598014000, 0x32e8c24d1cee432e}
    },
    {
        {0xa998c731389a48f3, 0x74fa8b44a0ab13b, 0x1ad03f591da71333, 0x2f03d178701bcb30},
        {0x8ff226bd0dd22c53, 0x26157e7a0aa47f2a, 0xe2531d8e88c5531d, 0x13d2bbc731281e5f},
        {0x76d7f22ef74ebe99, 0x245727aa206d8c55, 0x4e9bda26e39fe51, 0x72b21a3b6ea088d}
    },
    {
        {0x67aff49f723add69, 0xccae0df20e3d633b, 0x85d57c5cda0e022c, 0xa398b1d3e6f2db1},
        {0x3fda2e26bcb6fc68, 0x593102ff961e4b40, 0xcaca5e29529738de, 0x2af42667a6e9b6cc},
        {0x9d05ac0056c6910a, 0x51343579482ba8b5, 0x33398f54089da2a3, 0x1879180149c97c34}
    },
    {
        {0xfa93dc63c73d6490, 0x898847d037d78917, 0xf104b998c8ba5384, 0x1c6102bfd9c26df2},
        {0x3b13a7624fe64fc3, 0xae197dfb77fc7968, 0x855c3edfd013edc, 0x247f5769ca4aa6},
        {0x58bf743e0004f4eb, 0xa168da971a4635e8, 0xae0d93fc0aa0ca7c, 0x2e94bd91ee0eedec}
    },
    {
        {0x826688455b3034d9, 0xd7a8296917d9820f, 0xbf14001a68903362, 0x3029935cebc0e1b5},
        {0x45622b94048f7c58, 0x1025e0f2169c46c1, 0x93dccace2e8635fa, 0x2110fe2a3a9c405b},
        {0xe6249e1fd6ae6204, 0x359cea9c7fc56811, 0x4561c87d295edc47, 0x3462ff6269ff9b7f}
    },
    {
        {0xe88503091bf18fdb, 0xc7c9e48c7792429a, 0x7c2bedc34044daad, 0x239b54131c85ebfe},
        {0x9f92ac6cdf6d115c, 0x64fe79c6ea405241, 0x3fdbbe356870f930, 0x3c0d419e26ff24c1},
        {0xeb4e19e81548807b, 0x30d9ca531360e746, 0xe7fd824c32ef0f3d, 0x25c98a72c313174a}
    },
    {
        {0xed7835758762c591, 0xd3a5813b88ed365f, 0x954d02a8633dba6f, 0x3da1af9d7eb3a01e},
        {0x86a8692d3ed59690, 0xf2873c2381bf29b6, 0x5d8735bb1f3f459, 0x3c9a66efcbdbfd6e},
        {0x7acc7d7a0e1d24a3, 0x8614a6c50e15e4f7, 0xac5ee237c5548dd4, 0x12061a68b6963446}
    },
    {
        {0x81bc9093c7730d5, 0xbf3e57fb7d94a12f, 0xab7caef0406ad333, 0x30d704e038c83cee},
        {0x53fd9bef62ab35ab, 0xdd9258a43a400a0e, 0x41fc71c1f14a3fe0, 0xaafb95e685e323a},
        {0xbb168efcfbc6417d, 0x6eec41829c340ecc, 0x3e1a203ea728cf86, 0x32403a5339001606}
    },
    {
        {0xaa842cc888cce8e1, 0xaf60b8e8cfa84e30, 0xa8345e318e18911e, 0x23adb957cfe95986},
        {0x9b565aa4fc6cbed, 0x715714218a6da1db, 0x60740ecb2b402402, 0x3446170f139a28ee},
        {0x2d56545ce19df759, 0x2e62009452ac4624, 0xf834fd669efdc382, 0x3cdb040c5a2c8135}
    },
    {
        {0x2c093b07989ac45b, 0xbc5a7ce41629b4d8, 0xf9f8f9ccd52de847, 0xa6852ff99c0df59},
        {0x62ec3921cae6ad0c, 0xed01dd4b15bc12e2, 0xcf099203d7296486, 0x10c70f52d8e4c35c},
        {0xe3afb13d98e0aa36, 0xd5c2e410a19ecae7, 0x7ef462f8ef00f1ee, 0x3b2666c865ffaf5f}
    },
    {
        {0x2a34a9799fb10dea, 0xae3b7ac93a88e642, 0x9ce2e0a5b4676e62, 0x35338d2e290f6835},
        {0x704c2116789cd3e, 0x55c9408a44e87b39, 0x9a178778cf8123ac, 0x2a237d751ce80e22},
        {0xe73cc5f3949b8dac, 0x25fcebdc28f57fc2, 0xb8f4c26538ae8063, 0x160d42c37b816d52}
    },
    {
        {0x78bba3a1b4334fec, 0xe1ad733be7312e24, 0x166c29284c5e74cf, 0x1e39c10d204c6e},
        {0xeba34937ed572fb8, 0xec650563d7045e13, 0xbf694cf0e16bc82c, 0x14394f78ca804fcb},
        {0xa28d8e959c93e39c, 0xfe2361a2d86799e3, 0xb04a4d8890bfaa19, 0x3bd58529949c0ff6}
    },
    {
        {0x29225c95f5b1b6f9, 0xa6deebafdf12f757, 0x4d08632fbf4f058, 0x22ca57e20c30a4e2},
        {0xbd76f38890b3567b, 0x26cf81518916ab2, 0xe6096fe367359511, 0x1f5e2a08564c51ca},
        {0x522b7903b745f6ae, 0x97976d9feb2f329a, 0x4042a062305c3dd, 0x10e8bfbac34f6ab}
    },
    {
        {0x53a7679692da3aa1, 0xe450599e85d31d58, 0x7b0eb8260f95a840, 0x1ace63dc713e7378},
        {0x725231ba432706f4, 0xccfededdca80880, 0xeba96b0dfbc1ccb5, 0x2584d3df4dd8a065},
        {0xe55f4913a1b47696, 0x34767187e1938949, 0xdbe1913ab957b7f2, 0x3c4be85646076541}
    },
    {
        {0x96165fe1910385e3, 0xd8d34657e37bf741, 0x2dc65b5bd92b7412, 0x17c70695eabaad8c},
        {0x1aa94fbcda906296, 0x92b63261bad15d4, 0xde1fae454d20bc2, 0xff4dd19e7bb91c},
        {0x9a3c6bb3b3792b29, 0xba9a9d2d8c8f32fb, 0x90cae23b992784b0, 0x682d0d05588a0a4}
    },
    {
        {0x8bea2f0e3b07fdae, 0xa2bcf89d80d35726, 0x544cd1414cc270fe, 0x113a9293d2324718},
        {0xae456164d267504c, 0x571cb023dbc1ce73, 0x21bac9730f19acbf, 0x3233efcc4435feb},
        {0x8c75648ce93bee2e, 0x6a7b2664251ea438, 0xca0e6900ef478974, 0x2ea2eb8e4287afe1}
    },
    {
        {0x5acd5490088631ea, 0x796fd55cbfe132ea, 0xca378169084f5b20, 0x3bf94c0b770e6732},
        {0x3c7cc5fe22e9da10, 0x8c8312f4ace0a8a5, 0xc87567978ce028f8, 0x5a6f235fb313cd5},
        {0x2e6558b92407dcaf, 0x47e50ce3601012f4, 0x1e5797dd5bec08f6, 0x3f8733eee4c3467}
    },
    {
        {0x94d2410224bcb62d, 0x3a926c5d9a86b7d4, 0x4e194b53953a44be, 0x352e9b3d78b5bcc},
        {0x54883a363d4cf9d5, 0x11f8990c505f0d36, 0x6bc