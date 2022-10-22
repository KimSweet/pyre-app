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
        {0x54883a363d4cf9d5, 0x11f8990c505f0d36, 0x6bc1b45721bf8c66, 0x1741726454535739},
        {0x6f9a3ecf74a296b, 0x5de95fe78d089d68, 0xd73cd49e13d43129, 0x2093f7ce8f9a0900}
    },
    {
        {0xe9cb00b14e26ff0d, 0x3f08fd94461dc18e, 0x631adca53058abce, 0x3214d344acadc846},
        {0xded7eb4dbd85489a, 0x88fec23b8cd8b77, 0x16d4ed13eab05211, 0x2846ac03154cebb9},
        {0xfac2a0ad57a4f26, 0xc1f76ecd19989adf, 0xaf30edcd16db54f2, 0x126d20470a443867}
    },
    {
        {0xcff7162b34203071, 0xe55b077617c9a757, 0x2130b1adac59d068, 0x14c5aaf1e7b110eb},
        {0x699dd6dbcf0482c0, 0xea319e0d0b2bb999, 0xaa9e419d224d713d, 0x1f4d7ca828085388},
        {0xe0ce736d12ec2b2e, 0x2f38bcf04ebf093c, 0x4b4b4eb19457afe9, 0x36a6b22a47328281}
    },
    {
        {0x787526c6865dcd1e, 0xc2680fe54617f4a8, 0xb727dbb67712e717, 0x3a271ba53713445c},
        {0x806dc7288ade48b8, 0x37ae24211f9b6b9d, 0x8ca3d974dbf15054, 0x10fd6d9432eb0b68},
        {0xec73bef3a5597993, 0x911600cb416be443, 0x3ea4d6875cf79676, 0x1b77d3b73ff96642}
    },
    {
        {0x599dae5eba7bbf12, 0xad64c1aab4e1e894, 0x5d661ccb5ee325bf, 0x126b7751010f9d3f},
        {0x5ed0e07555bb26cd, 0x6e878aa29bf2c2e8, 0xf5a5eeccbaa31dc1, 0x1d3867eb4e090941},
        {0x2937ca036763d28b, 0x86e99a452605b663, 0x724c2748daf8484b, 0xebc687217853e09}
    },
    {
        {0x4dbc428bc8ad6e5d, 0xa2f7ba399263b882, 0x7bf0cdf85013257c, 0x28aeab12f70ef4a},
        {0x3c7790781e18b6e, 0x1bb3023fe1e655cb, 0xed1fdfcb455dca1a, 0x32e02d39a4d657a},
        {0x44e6d9c3a1dff228, 0xdf469cea3c0a5407, 0x299c3245b897c072, 0x2be7edf85aee84d5}
    },
    {
        {0x7cef1e98b43bf15c, 0x5a8dd042cde4ffe2, 0xd86af3fcf5e44a3b, 0x126fff14c130fdf6},
        {0x902d3cbb3b8bffd3, 0xd0510141c9be133a, 0x1153608479eba1e3, 0x33b9a4fa153248fb},
        {0x2267900dcf1e0fe4, 0xaf0c04b7861398c6, 0x55b20fd2619336f9, 0x3729ba618d213b74}
    },
    {
        {0x7bccad65b5fd53a3, 0x275fd70abbee0824, 0x6fce1c43407f5ddd, 0x381402c3966b0d15},
        {0xd4e90f5f5d1b1215, 0x7abfb980598b6f39, 0x6cc413a7353c523b, 0x3af9e5c6dbcecf69},
        {0xfc86b3533d23176f, 0xf2f83c14f801bf0f, 0x5fb324c8b8b84f4c, 0x2a9949609d62d389}
    },
    {
        {0xfca79d23caa474da, 0x94af585882c48b4, 0x9184e6e773524de, 0x1971a4bd05472cc6},
        {0xe14a7a9f4d347481, 0xf68eb0d753ed0146, 0x624211b6c3d94cff, 0x399c54dc6cd81b81},
        {0x86039539dbb961f9, 0xa5af68dc06d8ea6, 0xcc02fcf05e368eed, 0xf64acd9952a945b}
    },
    {
        {0x88c5c3ea3b0286e6, 0x8c0cf8675f0040d5, 0xc0f11c1177699ea2, 0xe3cc78066df561b},
        {0x49162b2f404f976c, 0x9a40001b3ac29cdd, 0x17287f8ca8386222, 0x39ca8d14934343bf},
        {0xa8dd36db44116537, 0x42dbe51eb9216283, 0xfec6c18c5ea56c1c, 0x9b0bc57ea6681fa}
    },
    {
        {0x53684675590d10f8, 0x228bd6ed1447104c, 0xcac8753557c5e945, 0x2533527c9ad29ad6},
        {0x5e26e312638c73b4, 0x34e1114452f840c, 0xc90124a9e02e5aad, 0x2af2662d93aa4250},
        {0x76bb15558221d4af, 0x41d2a02a322e09b9, 0x29727b4d6c29e353, 0x13f30e86ab0297f6}
    },
    {
        {0x8b113723e368b29c, 0x2ebddd5dcfd07680, 0x90027a89063fd6b, 0xab82f5420ead368},
        {0x6102c2fbeb0b8f83, 0x37caec74787f8363, 0xef4c7fedf4d49d09, 0x157481ef03f526da},
        {0x897dc99e348f8989, 0xfae2d8c6ca328b03, 0xd2a217387ae7e8fa, 0x2309412d902ce2d3}
    },
    {
        {0x57895d8995bb037b, 0x4f303912d7010f4, 0x89d126adee61fd7b, 0x16ae40bb98717e4a},
        {0x970b8cda0d943140, 0xd07503f516f70525, 0xb14ed69e29e5ede5, 0x2316911f23d9bed1},
        {0x632e10c13ba9d605, 0x23723cd16be7a1a3, 0xc0804d9b3264d489, 0x25b18b66bd5a14b1}
    },
    {
        {0x2cc13abb89f41136, 0x7b209265228a3e0b, 0xde1b3e0db09f17e0, 0x10e37b1b53ecfceb},
        {0x765eb14dd8c343a4, 0x3359bbc963368294, 0xeb4667bd15fd4a6c, 0x2db8142000298d91},
        {0x916a19d68c0ed401, 0x5002ac7be8c90d22, 0x8ae3857c98f24376, 0xb2557905a7150c}
    },
    {
        {0xf2b38d5f2758254d, 0x236745488b58741a, 0x394898e9d7458c8c, 0x37be2b56562adda1},
        {0x4aa28e0e6f54d290, 0x115bb413d8c4a639, 0x3944ec613d50506e, 0xbc68674dac60a3e},
        {0x82db6a2e85fec32c, 0x97802c924aadd00a, 0xbb6cc8685d8b265f, 0x16b975c2e70b76e6}
    },
    {
        {0xe2f39f5ef957115b, 0x9a9db22a4623e0fa, 0x86f28972da216598, 0x11dc93268964d29c},
        {0xd8842bd61b12b92a, 0x6b1e45e4a6b4da39, 0xc2541381b20e4fc2, 0x3cc006d14574ded2},
        {0xfe0a6647ec349b4a, 0x7d7f9c30364402f9, 0x8f30b3425f1e6b75, 0xa08c94f56352fda}
    },
    {
        {0xe8678e25a4d59721, 0x7c2331e36880e306, 0x82ad2f154d53292f, 0x38f905d3bf125a0d},
        {0x37c5ba5cf32727dd, 0x4e50703bbe74875c, 0x6e81ccf687c1edf3, 0x13d5a0a5cd167d3e},
        {0x549db53e76170f2d, 0x6601954d27f0614d, 0xa2e8516c0a8be8db, 0xe97e0bdc860ec97}
    },
    {
        {0xab07a7c64e7a0c19, 0x3231ef6a85c561a2, 0x45cb8d5c9e495f6c, 0x3c130965bd821488},
        {0x4e85b1262b64c882, 0x148a4053173c6bbf, 0x2d30540d2bdf16b4, 0x1c4069538aad6db3},
        {0xe6f0d54ae64a6b4c, 0x8e435e285f5a0431, 0x89f8a4e55b2e5266, 0xc59b65276e7adbf}
    },
    {
        {0xb3c5e9a0a063ba3c, 0xa5f4f9456cd30d09, 0x6d04f16139358814, 0xfe50ec7b61f34d3},
        {0x397f9724c5df2d2c, 0xebd5168a65e7dd00, 0x6e2d8f4b4688dfcc, 0x2089bd58ed27155},
        {0x4edc28aa719ba453, 0xd106c9909fe6d1bf, 0x583c7c64a6b2b9b9, 0x337410bcfb086e51}
    },
    {
        {0xab6b2a207aa0b5dc, 0x4a8b65d7af08b29c, 0x933af8749e812390, 0x279107e984004c7f},
        {0x905ad996b3c96494, 0x64c09614294ad370, 0xe3a6ebea9d5f50c7, 0x39f0c91fd7487f70},
        {0xfb555601b96a98f6, 0x2779c5a69548b485, 0x1024d8abadf302ac, 0x9d7b11afa205c31}
    },
    {
        {0x28cc587976dcbd5f, 0x7ec12e67d9fd9bff, 0x8519c024bfaacb31, 0xc3c59eef0b57c4},
        {0x7049bc5718274ce, 0xc5d45c2b8efbc27b, 0x1f2519b69fd58b2, 0x21d203679cf4943f},
        {0xdf1c276d845b18b, 0x83b415bcfd6f4794, 0x18cd69a7c02ec588, 0x28286f8440aac608}
    },
    {
        {0xab9395e8f09c0e5e, 0x54e90df06eeabe37, 0x989b955540f5df9, 0x47eea2cb710d36a},
        {0x1ebb22981a2358d4, 0x978b30395e4ae485, 0x9b80f8337febb2dc, 0x6eadd7dff66e6fc},
        {0x8235f76b05fb36f3, 0xe81d3e6b55c01c67, 0xef1c4fbfd4f2689f, 0x356208269cd6bf63}
    },
    {
        {0xdade3c9e413ae12e, 0xf0e6ec9130474658, 0xaf6a528f73acabe0, 0x25fa114c625e684a},
        {0x46eb556fec530561, 0xf037878098d1e6fa, 0x16665ada231de2c6, 0xe5526a3c3f20a1f},
        {0x8cf9f26ffb620afb, 0x10b561ad3be8bf53, 0xd095012a132c7d3f, 0x29dcadbf2a3da8a2}
    },
    {
        {0xc1f246cabd2b3006, 0xa36999931ad6917e, 0xa86d5a37a14ebfc6, 0x233db2873238ccef},
        {0x6acabbbf7f09c6ab, 0x62e42b55c506b5ac, 0x20d3e5414eabcf58, 0x3047b6ea2b2ead12},
        {0xebb686baebe27e60, 0x6e299977bf344ce, 0x62074c04b5eaa97, 0x2f8be92e4b475d6c}
    },
    {
        {0x68ec476c77321432, 0x6dc59804560e83e6, 0xad6ec6887fa80a57, 0xd2381657826abc9},
        {0xb377a593d24bcde1, 0x9a3338ee6dc43188, 0xfda6b04c6b645795, 0x1ebafbaa3cac50f4},
        {0xf53a7e9aa0eaf7a2, 0xc425d1cf708205ee, 0xc4bf63055e40b848, 0x31fd982712a1810}
    },
    {
        {0x6aaec40a5ee97dc6, 0x1b740fec535e8d07, 0x72eb71573af7f8dc, 0x32a6cfd27721af},
        {0x4422e0763e1715cb, 0x2cc98a9c36481c08, 0x90a04c2c1100cf7, 0x14bdba391dc19c19},
        {0xf7ed8041fc74c1ba, 0x2da17664b7e0a39d, 0x7f194ed781738bd0, 0x185a0fb1e41d78e2}
    },
    {
        {0x362d5eb8cf158562, 0x2cbda32193e3b946, 0x54a1587b53b6d3e, 0x3f6a83a8d453698e},
        {0xe4f331c807d7dbe4, 0x268c8fd3827cafa, 0x8128d4066a80b733, 0x3ac9356638ef0909},
        {0xc173b74baf5d10c0, 0xef4884b5f01dcb2a, 0x8ee4fbaf7d1af482, 0x3a631a390c1ace3a}
    },
    {
        {0x8db20233cb7664ef, 0xcbd2b0d64c8e2b19, 0xb09d212d4b96af9b, 0xa41894a30594d96},
        {0xc87ad145936cc7b5, 0x831d623d07e2d55a, 0xb9f94b89928f0348, 0x32480b57ca35650c},
        {0x8df84ce2e7f6469f, 0x901e9cc791984cf9, 0xc8fcb9b481d64cbe, 0x3f5d039f9330361e}
    },
    {
        {0xbf7db6c50e4b6c8e, 0xec86607f277ed803, 0x788b68697fc5fc3d, 0x31e6a675fa09e651},
        {0x1132c9835ce2f214, 0xe753150f8c8b375f, 0x8621813806da885e, 0xefb3b636dc3218c},
        {0x4ce5ce169e972cad, 0x36c4e02c437c353d, 0x91d0f983117961d3, 0x3fab66c8f61b43f4}
    },
    {
        {0x26e7f148037e4831, 0xc898cea85a6d9ce7, 0x296eb709b0bce897, 0x13c7e41ce4a9413a},
        {0x364510c0cc6957d1, 0xc25f1640446d6363, 0xa38c8faccf2af7bc, 0x302f893eb7f3a293},
        {0xf47cdc9a193b6a1a, 0xbd3e81440b147a51, 0x1b8e11dc417ad50b, 0xbc7ad99db78ba74}
    },
    {
        {0x5693220ff22b64e3, 0x95b8a7d6f5f07e88, 0xbb3aaa303d8a574, 0x20f50189f52021f3},
        {0xac8d038b73e50e93, 0x613109576b0dfb1e, 0x4ac8d41e35f9b309, 0xa7ad75a9d37c68c},
        {0x9c979eb72d6864c7, 0x8f1b33a9db15c462, 0xd9dfc2decd86ff41, 0x536ee7d16b7b5d5}
    },
    {
        {0x624a1196b5b7005f, 0xb8d9cdf932bdf18, 0x14682525e48adc4a, 0x1d434955ccf03ab0},
        {0x719a6381517b8c7a, 0x6168713e68dfa531, 0x9b6cf63daf06a7ee, 0x1d259cdc7f7100c8},
        {0x6f1e012d7c9270c9, 0xe523c121eae14ae6, 0x50e570fed81bd490, 0x3604d717343ea349}
    },
    {
        {0x4eb31e3e9fb8bc15, 0xaa82d889ed027926, 0x861770ba9013af2c, 0x379ab47829cd822c},
        {0x6f9b1e3a7b6dce3, 0xc5c9ef5c6b7a53d0, 0xc8d12ce69f47f1d6, 0xbc256406e070545},
        {0x6440d55f63d23009, 0x74c5732854d7e658, 0x4f7e9fd81fd40c7b, 0x399992d613926dad}
    },
    {
        {0xc29845928af2930, 0xa0130ffd9a9f0e2a, 0x48033877dafbdd89, 0x8c39d86214ce71a},
        {0x9af58f43601d6790, 0xd1af4f75b46b599b, 0x4a8b0b5e6e229017, 0x187b443781223437},
        {0xe4304790543ef2b4, 0x9c231e915d799bd, 0x200b86e24d27b2ce, 0x2b71199749ffc729}
    },
    {
        {0xf4ba819f140a9647, 0x959dd33caab9515e, 0xfd99be65b9533f42, 0x28a03868f0a95555},
        {0x6afe5aee6300eeb3, 0x950ea44539e2fa43, 0xbd9aae96c7978e8f, 0x2e3b4f7256ec9b73},
        {0xcc62f85dcccaf357, 0xb56baaa116eae113, 0xd39121b0dcf3259b, 0x46f25e4866044af}
    },
    {
        {0xfa220016b44669a2, 0xfbe99bbe5092f557, 0xe04b667a942bafa6, 0x26854edc78b0bd2e},
        {0x93c3a940486a4eb8, 0x74cbbc7bd198d4a2, 0xd64f6e74ed8521f2, 0x80843fa28104df1},
        {0xd544d8f569cb4c5d, 0x9be59548e6b93d2