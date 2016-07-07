/* q128.c - Encryption and Decryption for 128-bit blocks, 128-bit keys

Set up the key by calling SetQ128Key().
Do encryption and decryption by calling  EncryptQ128() and
DecryptQ128().
The key and the data block are both arrays of four 32-bit words.
 ***Important***  Edit q128.h for your target machine and compiler.
 ***Important***  Edit q128opt.h for optimizations
-------------------------------------------------------------------*/
#include "q128.h"
#include "q128opt.h"
#include "ftab.h"
#define TENBITS 0x3ff
static UINT_32bits ExpandedKey[64];

void SetQ128Key( UINT_32bits *key )
{
        register UINT_32bits *expkey;
        register UINT_32bits b0,b1,b2,b3;
        int i;
    expkey = ExpandedKey;
    b0 = key[0];  b1 = key[1];  b2 = key[2];  b3 = key[3];
    for(i=19; i; i--)        // 19,18,17,...,3,2,1
    {
        b1 ^= (Ftab[b0 & TENBITS]);  RRotate(b0)
        b2 ^= (Ftab[b1 & TENBITS]);  RRotate(b1)
        b3 ^= (Ftab[b2 & TENBITS]);  RRotate(b2)
        b0 ^= (Ftab[b3 & TENBITS]);  RRotate(b3)
        if(i<=16)            // 16,15,14,...,3,2,1
        {
            *expkey = b0;  expkey++;
            *expkey = b1;  expkey++;
            *expkey = b2;  expkey++;
            *expkey = b3;  expkey++;
        }
    }
}

void EncryptQ128( UINT_32bits *blk )
{
        register UINT_32bits *expkey;
        register UINT_32bits b0,b1,b2,b3;
        int i;
    expkey = ExpandedKey;
    b0=blk[0];  b1=blk[1];  b2=blk[2];  b3=blk[3];
    for(i=16; i; i--)
    {
        b1 ^= (Ftab[b0 & TENBITS] + *expkey);  expkey++;   LRotate(b0)
        b2 ^= (Ftab[b1 & TENBITS] + *expkey);  expkey++;   LRotate(b1)
        b3 ^= (Ftab[b2 & TENBITS] + *expkey);  expkey++;   LRotate(b2)
        b0 ^= (Ftab[b3 & TENBITS] + *expkey);  expkey++;   LRotate(b3)
    }
    blk[0] = b0;  blk[1] = b1;  blk[2] = b2;  blk[3] = b3;
}

void DecryptQ128( UINT_32bits *blk )
{
        register UINT_32bits *expkey;
        register UINT_32bits b0,b1,b2,b3;
        int i;
    expkey = ExpandedKey+64;
    b0=blk[0];  b1=blk[1];  b2=blk[2];  b3=blk[3];
    for(i=16; i; i--)
    {
        RRotate(b3)    b0 ^= (Ftab[b3 & TENBITS] + *--expkey);
        RRotate(b2)    b3 ^= (Ftab[b2 & TENBITS] + *--expkey);
        RRotate(b1)    b2 ^= (Ftab[b1 & TENBITS] + *--expkey);
        RRotate(b0)    b1 ^= (Ftab[b0 & TENBITS] + *--expkey);
    }
    blk[0] = b0;  blk[1] = b1;  blk[2] = b2;  blk[3] = b3;
}




// q128.h -------------------------------------------------------
typedef unsigned long int UINT_32bits;

extern void SetQ128Key( UINT_32bits *key );
extern void EncryptQ128( UINT_32bits *blk );
extern void DecryptQ128( UINT_32bits *blk );




//q128opt.h ----------------------------------------------------
#include <stdlib.h>
#define RRotate(x) (x) = _rotr(x,10);
#define LRotate(x) (x) = _rotl(x,10);

/*------------------------ Note:

  The macros RRotate and LRotate here are taking advantage of the 
intrinsic functions _rotr() and _rotl() to do rotation with a single 
instruction.  If your compiler does not support these functions, 
then you may use the following (slower) macros:

#define RRotate(x) (x) = (((x)>>10) | ((x)<<22));
#define LRotate(x) (x) = (((x)<<10) | ((x)>>22));

x must be an unsigned data type so the shifts will be logical.
--------------------------------------------------------*/





//ftab.h ---------------------------------------------------------
static UINT_32bits Ftab[1024] = {
 0xd6d92632,0x5e84404d,0x4f341282,0x71654b06,0xd48d6a0b,0x245becc4,
 0xc8f84d80,0x22c620c9,0x66aa8b02,0x0ac697ff,0x8b755a36,0x2577931c,
 0x438d17b6,0xbb7b1bd1,0xe0a8f51e,0xf4fd583d,0xbeceeb95,0x7945c1ae,
 0x29ce9628,0x3d7965cd,0x80cfbdb9,0x2f535a25,0x7666a9bd,0x6df2324b,
 0x98731a06,0xe4d32444,0x265faf55,0x41895427,0xf2d2c55e,0x8151930f,
 0x77a888a3,0x9cba9a32,0xa7ec629c,0x55dcf904,0xb35b9179,0x1ab8e42e,
 0xa0ef8027,0xdb4c5cde,0x9fc2a9d3,0xa9512439,0x9c08cb5c,0x4bfd92b6,
 0xc23eda7f,0x037833e1,0x40177a91,0xbae53567,0x774ad665,0x3cb744d3,
 0x6e8a01aa,0x65d2b8e3,0x0507a12a,0xef69c3cb,0x230801d7,0x0bbae78f,
 0x62630b36,0xed6d805a,0x5aaf9ebf,0x721d78e7,0xd33cd9de,0x6618da6c,
 0x9dc6ea42,0x0d272b82,0x3559ef65,0xdcfdef0b,0x865271b4,0x3621dc84,
 0x885d667f,0x92e58251,0x2e9d7b3b,0xe9165100,0x99bd3b18,0xb1ed8386,
 0x84563225,0x446cabcb,0x7e462315,0xa2bbcc1e,0x3be4a9c0,0x320a0276,
 0x416b0ae1,0xc6a755e3,0x5c8003dc,0x36c38242,0x97e2237b,0x2ae6aa61,
 0x8a5925ee,0x3b56f8ae,0x26bdf193,0x96ce5ca3,0xe51d055a,0xad2af563,
 0x2b9ada11,0x9f70f8bd,0x3f9f789a,0x89934761,0xa8cf0a8f,0xc78b2a3b,
 0x8f5e84c4,0xb8b1795e,0xafcce834,0xd9aa4189,0xc28c8b11,0x7636a615,
 0xf2609430,0xeca3a144,0x7869be76,0x12c8612e,0xd18acb21,0xcc61c21c,
 0xeddfd134,0xad7afacb,0x7f6a5ccd,0x0c0b545a,0x584983e8,0x04998f9c,
 0x969e530b,0xe21ee7e1,0xfff5eedc,0xfe3bcfc2,0x97007dbd,0x66fa84aa,
 0xa375ed00,0x3509e0cd,0x1b76c530,0x70193b76,0x86e020da,0xc9366c9e,
 0x49f9d127,0xae52c682,0x260fa0fd,0xe380c957,0xce358e25,0x02044391,
 0xaeb09844,0xf31ce440,0xf0d686cf,0x8cc4e9e3,0xbe2cb553,0x1e933adc,
 0xc312a5a7,0x1d0957fb,0xa1c3ffff,0xbd5486b2,0xe8d8701e,0x6e685f6c,
 0x1bc4945e,0x062f9d63,0x84063d8d,0xc1f4b8f0,0xa7bc6d34,0xc4f319da,
 0xf81452a1,0x4cae7fa5,0x1dbb0695,0xaa9b46b6,0x6bddaf28,0x61f96611,
 0x9a27563f,0xc2dc84b9,0x6530e625,0xe7494963,0x6ff671da,0xb8532798,
 0xc06a9646,0xcc839cda,0x9eeed60b,0xa70e3c5a,0xf0868967,0x02544c39,
 0x87cc5f02,0xb3b9cfbf,0xf6f91bac,0xdcade0a3,0x8b9704f0,0x6cde4d93,
 0x64aec893,0x3e515984,0x7bf3d351,0x3eb30742,0xbe9ee43d,0xb15fd2e8,
 0x2c7b666c,0x01ce211e,0x3b06f706,0x05e5ffec,0x24e9bdaa,0xfda1a2e5,
 0xe04aabd8,0xe9a4006e,0x019e2eb6,0x8d0ac8fd,0x73d359f9,0x6a43819e,
 0x00500fa8,0xda302cae,0xc0d8c728,0x62d15a58,0x61a969b9,0x1e216bb2,
 0x0892dbc6,0x3a7a8776,0x34259f15,0x79a79f68,0xf96822d1,0x7f88020b,
 0xaf9ce79c,0x017c7070,0xf8445d09,0xee15b3bb,0xe3629791,0x20203d9e,
 0x53413509,0x25279cb4,0xdf378d84,0x8921160f,0xa89f0527,0x413b0549,
 0xad98a40d,0xfb8e3f86,0x00000000,0xd717072c,0xe6353913,0xacb4dbd5,
 0x1f0d146a,0xc411471c,0xb9cd092e,0x41d95b8f,0x74d0bb42,0x86027e1c,
 0xda827dc0,0x57d8ba95,0x12986e86,0x9bb97889,0xc9843df0,0x122a3fe8,
 0x556ea86a,0xd8346f3f,0x693bb27f,0x53113aa1,0x2850b89e,0x0ce90a9c,
 0xfb3c6ee8,0x7a6dfde7,0x917fef76,0x2a54fb0f,0xe2acb68f,0xe4832bec,
 0x2e7f25fd,0x110203a1,0xaacb491e,0x18eca817,0x9e5c8765,0x14b7f3e5,
 0xc146e99e,0x2e2f2a55,0x47a6c944,0x23ba50b9,0xd2f2f8c0,0xfbde302e,
 0xa494517d,0xb5740c1a,0x72af2989,0xee45bc13,0x03283c49,0x6fa67e72,
 0xf767351a,0x1a5abae8,0x197286a1,0xe71946cb,0x0f7367bb,0xdd33ce15,
 0x31c060f9,0x67d6fb72,0xaee097ec,0x28e2e9f0,0xe7ab17a5,0xba076ba1,
 0x2595cdda,0xd43f3b65,0x25c5c272,0xc81a1346,0x177d916a,0x9b5b264f,
 0xe166d400,0x9ebed9a3,0x7ef4727b,0x611b38d7,0x5dfc73ac,0x0c5b5bf2,
 0x8de8963b,0xc7db2593,0x31223e3f,0xd7470884,0x606748a7,0xffa5e174,
 0xf3feba86,0x40f52457,0xa3c7bc6e,0xdc4fbe65,0x6233049e,0xc26ed5d7,
 0x4f8643ec,0x468ab69c,0x53a36bcf,0x558cf6ac,0x95043e2c,0x1b26ca98,
 0x4867ff91,0x85c81c93,0xb60c3ffb,0x897119a7,0x4ad1ed6e,0x7480b4ea,
 0x0beae827,0xd0f6bb51,0x58198c40,0x6989e311,0x5f1a6efb,0x696bbdd7,
 0x6847c20f,0x6c6c1cfd,0x1ec33574,0xf64b4ac2,0xf41f06fb,0x00b2516e,
 0x644c9655,0x8c94e64b,0x6648d5c4,0xa2ebc3b6,0x4c1c2ecb,0xf7856bdc,
 0x7adfac89,0x4837f039,0xae02c92a,0x35bbb1a3,0xe461752a,0xf7d56474,
 0xd210a606,0x718715c0,0xa4c45ed5,0xbab53acf,0x1c252823,0xcb807e61,
 0xcdafe302,0xaa791870,0x0b58b949,0xa00ddee1,0x60d519c9,0xe1848ac6,
 0xd9481f4f,0xf148a879,0x64fec73b,0x3c551a15,0xe5af5434,0x4d605ebb,
 0xa55a7063,0x3c0515bd,0x1deb093d,0x0d957aec,0x3ee308ea,0xccd39372,
 0xd38e88b0,0xfa401e98,0x8f0e8b6c,0xb023a298,0x9207dc97,0x7c126f2c,
 0xd8863e51,0xcd4dbdc4,0x382ecb4f,0x6a138e36,0x631f7b46,0x19228909,
 0x1c75278b,0x50db582e,0x90039f06,0xa9b37aff,0x06cdc3a5,0x210c4246,
 0x8fecd5aa,0xb227e109,0x3d9b3b0b,0xb92f57e8,0x23ea5f11,0x7839b1de,
 0xcaac01b9,0x127a3040,0xf282caf6,0x9a950751,0x8e22f4b4,0xfc6f83fb,
 0x56f4c54d,0xbccaa804,0x0f91397d,0x60851661,0x807decd7,0xeadc338f,
 0x51457698,0x9f20f715,0xe4317a82,0xd7a55642,0xf2309b98,0x3f2d29f4,
 0xeb121291,0xdbae0218,0x99ed34b0,0xfd13f38b,0x91cdbe18,0xc9666336,
 0x7b118d97,0x042bdef2,0xed3d8ff2,0x179fcfac,0x63ad2a28,0x32b85318,
 0xcdffecaa,0x724d774f,0x21ee1c80,0x42a1686e,0x2a04f4a7,0x95b66f42,
 0xde4bfdf4,0xd240a9ae,0x4a81e2c6,0xa82d5449,0x7d3e10f4,0x614b377f,
 0xfaa2405e,0x3fcf7732,0x90b1ce68,0xfc8ddd3d,0x8db89993,0x16e3bfdc,
 0xb30b9ed1,0x8229a0ee,0x4eaa3c34,0xb10fdd40,0x56a4cae5,0x84e4634b,
 0xd16895e7,0x6e3850c4,0x95543184,0x58abdd2e,0xbe7cbafb,0xc8a84228,
 0xdad27268,0xdb1c5376,0x71d71a68,0xbdb6d874,0xebf04c57,0xdfd5d342,
 0x852a4255,0xd66b775c,0xb4087c6a,0xcbd071c9,0xeb421d39,0xdd819f7b,
 0x4fd64c44,0x305e4e4f,0x7d8c419a,0xd014e597,0xdea9a332,0x1c97794d,
 0x45a28ad5,0x628155f0,0x912fe0de,0x43dd181e,0xfaf24ff6,0x4efa339c,
 0x9399f221,0x0eed490d,0xb4ba2d04,0xa193f057,0x942841f4,0xe136dba8,
 0xe7fb180d,0xf5337923,0x30bc1089,0xbc9aa7ac,0xcffbaf3b,0x6560e98d,
 0x33942cc0,0x0a969857,0x5788b53d,0x20703236,0x31906f51,0xa75e33f2,
 0x5987a2f6,0x6b3ff1ee,0xc5df6602,0xa25992d8,0x6af1d0f0,0x1651eeb2,
 0x5fa83f95,0xd8d631f9,0x788be0b0,0xb6be6e95,0xa121a139,0x19c0d7cf,
 0x095cfad8,0x09bea41e,0x872e01c4,0xc7397b55,0x990f6a76,0x1601e11a,
 0x17cfc004,0x3bb4a668,0x8abb7b28,0x809fb211,0x94ca1f32,0xb277eea1,
 0xcfaba093,0x5965fc30,0x9ac508f9,0x7f3a5365,0xef8b9d0d,0x37effd9a,
 0x949a109a,0x9f92a67b,0x90e1c1c0,0xf8f60c67,0x8a092a46,0xf8a603cf,
 0xf9382d79,0x6f142f1c,0x5aff9117,0xace4d47d,0xfe899eac,0x13564f98,
 0xd2a2f768,0x76d4f8d3,0xa2099d70,0x08c2d46e,0x42133900,0x07e1bc7d,
 0xf4ad5795,0xeef7ed7d,0x932ba34f,0x33267dae,0xcafc0e11,0x2fb104e3,
 0x503906e8,0x172d9ec2,0xf61b456a,0x6eda0e02,0x4e4862f2,0xc56d376c,
 0x526d4ad1,0xe9465ea8,0x448ef50d,0xea3e6d49,0x3952bb3f,0x2ecd7493,
 0xac068abb,0x59d7ad5e,0x877e0e6c,0xa397b3c6,0x069dcc0d,0xd63b78f4,
 0x7cf031ea,0x180ef6d1,0xca1e50d7,0xdf85dcea,0x8c76b88d,0xea6e62e1,
 0x090cf570,0xe54d0af2,0xb2c5bfcf,0x14e7fc4d,0xb7204023,0x7ea47dd3,
 0x52df1bbf,0x6582b74b,0xecf3aeec,0xc03a99ee,0x7e162cbd,0x3a98d9b0,
 0x0dc57544,0xa325e2a8,0xd5434b15,0xe687687d,0x6817cda7,0x6d406325,
 0x4714982a,0x102e7c79,0xbc28f6c2,0x78dbef18,0x2ab6a5c9,0xc3a0f4c9,
 0x7d6e1f5c,0x9c58c4f4,0x82cbfe28,0x21be1328,0x576aebfb,0x8e72fb1c,
 0xa6724c2a,0x4638e7f2,0x2b7884d7,0x40477539,0x5442d7b2,0xea8c3c27,
 0x1455ad23,0x2773d08d,0x387ec4e7,0x3ac8d618,0x4b4fc3d8,0x18bca7bf,
 0x83b78e58,0x53f36467,0x2723df25,0x4c4c2163,0x8598133b,0x1fbf4504,
 0x2fe10b4b,0x297cc746,0x46dab934,0x56469423,0x641c99fd,0x4cfe700d,
 0x8b25559e,0x5d1e2d6a,0xbc78f96a,0x24b9b202,0xef39cc63,0xc116e636,
 0x989144c0,0xefdb92a5,0x5d4e22c2,0x68a59cc9,0x77f8870b,0x7a3df24f,
 0x7ca03e42,0xfd43fc23,0x70fb65b0,0x905390ae,0x443ca463,0x6d106c8d,
 0x1529dd53,0x38cc9589,0x5935f398,0x2f03558d,0xb8e176f6,0xb073ad30,
 0x5e661e8b,0x11520c09,0x573ae453,0x8c26b725,0xddd190d3,0x97507215,
 0x27c181e3,0x0557ae82,0xf3aeb52e,0xd51344bd,0x9d96e5ea,0x42f167c6,
 0xa6c01d44,0x982315ae,0x2b288b7f,0xa171ae91,0x97b22cd3,0x919db1b0,
 0x13b4115e,0x7684f77b,0xc342aa0f,0x08208aa8,0x08708500,0xe5ff5b9c,
 0x4e186d5a,0x2800b736,0xd5a115d3,0xc4a31672,0x159b8c3d,0xfe6bc06a,
 0x967c0dcd,0x07b1b3d5,0x433f46d8,0xe8887fb6,0x4668e85a,0x45f2857d,
 0x2bcad5b9,0xd4dd65a3,0x72ff2621,0xb99d0686,0x8ec0aa72,0x2de548da,
 0xe01aa470,0x8355d09e,0x5e361123,0xe66536bb,0x5f4a6153,0x5dac7c04,
 0x23580e7f,0xb52403b2,0x93c9fd89,0xb6ee613d,0xc6f75a4b,0x3a2a88de,
 0x70ab6a18,0x4d305113,0xc3f0fb61,0x22247e0f,0x49a9de8f,0x8d5ac755,
 0x95e660ea,0xc088c880,0xc6450b25,0xf7373ab2,0xf1aaf6bf,0x3ce74b7b,
 0xfdf1ad4d,0x634f74ee,0xabe736c6,0x436f4970,0x4a63bc00,0x94784e5c,
 0x27918e4b,0x300e41e7,0x9be97721,0xdbfe0db0,0xed8fde9c,0x81e3c261,
 0xfed99104,0x33c42368,0x5ed44fe5,0x0753ed13,0x47f6c6ec,0x704934de,
 0x2cc93702,0x02b612ff,0x3f7d265c,0xa4760fbb,0x1a0ab540,0x09eeabb6,
 0xadc8aba5,0x13e41ef6,0x88bf38b9,0xd91810e7,0x523d4579,0x6734a5b4,
 0x370da35c,0xdc1fb1cd,0x04c98034,0x2db54772,0x4dd20fd5,0x86b02f72,
 0xbb994517,0xd044ea3f,0xd1dac489,0x4885a157,0x3902b497,0xc1a4b758,
 0x0fc136d5,0xff17b01a,0x5b83e167,0x7a8fa321,0x1579d2fb,0xeba043ff,
 0x50690940,0x802de37f,0xa6224382,0x6b8da080,0x0a74c691,0x7432e584,
 0x528f1417,0xa5e8210d,0x88ef3711,0x9a775997,0x0cb90534,0x292cc8ee,
 0x47449782,0x20c26358,0xc615048d,0xaa2917d8,0x494b8049,0x84b46ce3,
 0x73610897,0x7ba3dcf9,0x4510dbbb,0x68f59361,0x8279af46,0xbd04891a,
 0xce87df4b,0x553ea7c2,0xcb322f0f,0x5c625d1a,0x4f641d2a,0x325a0dde,
 0xa50a7fcb,0x11b052cf,0x1d595853,0xf563768b,0x98c14b68,0x3d296a65,
 0xde1bf25c,0x3671d32c,0xe3329839,0xf581284d,0x37bff232,0xdef9ac9a,
 0x8e90a5da,0x754e95f4,0x5b31b009,0xb4ea22ac,0x713544ae,0xce65818d,
 0x067f92cb,0x39e0ea51,0xb0c1fc5e,0xc84a1cee,0x6aa1df58,0xe9f40fc6,
 0xf1faf917,0x13064030,0x05b5f044,0x424336a8,0x0a24c939,0xc44148b4,
 0x6f4420b4,0x047bd15a,0x39b0e5f9,0x8bc70b58,0x0e5f1863,0xd1389a4f,
 0xaf2eb6f2,0xc9d43258,0x107e73d1,0x89c348c9,0x9cea959a,0x11e05d67,
 0xbb2b1479,0x73835651,0xf34cebe8,0xd36cd676,0x4540d413,0x5cd00c74,
 0x31723197,0xeea7e2d5,0x0f236813,0x81b3cdc9,0x7fd80da3,0xd7f559ea,
 0x03ca628f,0x3dcb34a3,0x33767206,0x2c2b69c4,0x51f727f6,0x829bf180,
 0x039a6d27,0x56169b8b,0x4d82007d,0x9d24b484,0xbde6d7dc,0x389c9a21,
 0x69d9ecb9,0xb792114d,0x44defaa5,0x8fbcda02,0x92b58df9,0x962c0265,
 0xcf19f1fd,0x7462ea2c,0x227471a7,0xc53d38c4,0x9257d33f,0x32e85cb0,
 0xabb7396e,0x30ec1f21,0x58fbd286,0x5b61bfa1,0x240be36c,0xb7704f8b,
 0xa69012ec,0x1f5d1bc2,0x8305df36,0x299e9980,0x5ff8303d,0xc58f69aa,
 0x7ddc4e32,0xe6d767d5,0x880d69d7,0xd46f34cd,0xff47bfb2,0x22962f61,
 0xa9e37557,0xfa101130,0x83e781f0,0xcf49fe55,0xfcddd295,0x2d07161c,
 0xe83a2ed8,0xca4e5f7f,0x75fcc49a,0x7915ce06,0x54f086dc,0xa9012b91,
 0x0ebd46a5,0xdf67822c,0xd9fa4e21,0xaf7eb95a,0x81019ca7,0xf118a7d1,
 0x00e25ec6,0x9b0b29e7,0xe2fcb927,0xec11f02a,0x857a4dfd,0x3497ce7b,
 0x1b949bf6,0x9d74bb2c,0xcc31cdb4,0xe3d0c6ff,0xbf00ca8b,0x36938dea,
 0x16b3b074,0xced7d0e3,0x6037470f,0xcd1db26c,0x6da23de3,0xbbc94abf,
 0x5a1dcfd1,0xc76974fd,0xa05dd149,0xf034d809,0xa4260013,0xb091f3f6,
 0xa5b82ea5,0x6786f4da,0x4bad9d1e,0x1e71641a,0xb59652dc,0xba576409,
 0xb1bd8c2e,0x2d5719b4,0x7331073f,0xac568513,0xb97f5840,0xbf50c523,
 0x0703e2bb,0x6764aa1c,0x20926cf0,0x012c7fd8,0x1cc776e5,0x9e0c88cd,
 0x995f65de,0xf44f0953,0xe86a2170,0x1fef4aac,0x7c426084,0x771ad9cd,
 0x2c9938aa,0xb8032830,0x4a33b3a8,0x751e9a5c,0xdd63c1bd,0x79f790c0,
 0x51157930,0xd5f11a7b,0xd8646097,0xcb6220a7,0xd689299a,0x879c50aa,
 0xb7c21ee5,0x4b1fcc70,0x0b08b6e1,0x28b2e658,0xb295b067,0xab056800,
 0x75accb32,0xbfb29be5,0xf5d127e5,0x6c8e423b,0x6b6ffe46,0x215c4dee,
 0xf9da73bf,0x7b41823f,0x48d5aeff,0x1405a28b,0xbfe2944d,0x347590bd,
 0xb45873c2,0xb65c3053,0xa0bf8f8f,0x937bace7,0x1ae8eb86,0x40a52bff,
 0xe24ee849,0xd3de8718,0x6c3c1355,0x1990d867,0x54a08974,0x375dacf4,
 0x508b5786,0x63fd2580,0xf98a7c17,0x34c7c1d3,0xd0a6b4f9,0x3e01562c,
 0x185ef979,0x5412d81a,0xb5c65d74,0x26edfe3b,0x35ebbe0b,0x02e61d57,
 0x15cb8395,0x0e0f17cb,0xfc3f8c53,0x5a4dc079,0xe0f8fab6,0x5bd3eecf,
 0xe1d4856e,0x8aeb7480,0x5c3252b2,0xab5567a8,0xfb6c6140,0xb3e9c017,
 0xec41ff82,0xf064d7a1,0x491b8fe1,0xa87d5be1,0x10cc22bf,0xf6a91404,
 0x0d77242a,0xda602306,0x51a7285e,0x109c2d17};




//ftab.c ---------------------------------------------------------
/*-------------------------------------------------------------------
  This program generates the Ftab[] array used in Q128.  It uses
  Blowfish as a random number generator.  The method is to start
  with an array, Ftab[], initially set up so that Ftab[i] = i for i
  running from 0 to 1023.  Then Blowfish is used to generate 1000000
  random numbers.  This is done by using the key
  "abcdefghijklmnopqrstuvwxyz", and encrypting plaintexts (Left
  Word, Right Word) where Left Word is always zero and Right Word
  runs from 0 to 999999.  For each Right Word ciphertext generated
  by Blowfish encryption, the values in Ftab[i] and Ftab[j] are
  interchanged, where i runs from 0 to 999999 (reduced modulo 1024)
  and j = Right Word ciphertext (reduced modulo 1024).  In this way
  we get an Ftab that is a random permutation on 1024 elements,
  expressed by 32-bit numbers where only the low-order 10 bits in
  each element are used.  Ftab[] is further modified by subjecting
  all the entries to a random non-singular 32 x 32 matrix of ones
  and zeroes.  The random 32 x 32 non-singular matrix is itself
  generated from random numbers from Blowfish.  The same key is used
  as before.  Then 32 random 32-bit numbers are generated by
  encrypting Right Word = 0...16.  Each encryption results in two
  32-bit numbers which form two rows in the matrix.  That's why only
  16 encryptions are needed.  This gives a random 32 x 32 matrix of
  ones and zeros which may or may not be non-singular.  It is
  checked for singularity by reduction to canonical form.  If it is
  non-singular it is used to act on Ftab as described above.  It it
  is singular, then the process is repeated by encrypting the next
  16 numbers (17...31).  Eventually a non-singular matrix is found. 
  In this way the random elements of Q128 are generated in a manner
  that does not hide any secret design.
-----------------------------------------------------------------*/
#include <stdio.h>
#include "blowfish.h"
#define TENBITS 0x3ff
#define UINT_32bits UWORD_32bits
static UINT_32bits Ftab[1024];
static UINT_32bits Matrix[32],Mat[32];

main()
{
        int i;
        unsigned long ki,Lw,Rw,Baseki;
        UINT_32bits t;
        char singular;
    printf("\r\n Initializing Blowfish...");
    InitializeBlowfish("abcdefghijklmnopqrstuvwxyz",26);
    for(i=0; i<1024; i++)  Ftab[i] = i;
    printf("Scrambling Ftab...");

    for(ki=0; ki<1000000; ki++)
    {
        if((ki&511)==0) printf("%8ld",ki);
        Lw = 0;  Rw = ki;
        Blowfish_encipher(&Lw, &Rw);
        t = Ftab[ki & TENBITS];
        Ftab[ki & TENBITS] = Ftab[Rw & TENBITS];
        Ftab[Rw & TENBITS] = t;
        if((ki&511)==0) printf("\b\b\b\b\b\b\b\b");
    }
    printf("        ");

    printf("\r\nLooking for a non-singular matrix...");
    singular = 1;
    for(Baseki=0;  singular;  Baseki+=16)
    {
        printf("\r\nTry starting at Rw = %ld",Baseki);
        for(ki = 0; ki < 16; ki++)
        {
            Lw = 0;  Rw = ki + Baseki;
            Blowfish_encipher(&Lw, &Rw);
            Matrix[2 * ki + 0] = Lw;
            Matrix[2 * ki + 1] = Rw;
        }
        printf("   Checking for singularity: ");
        {
                int row,col,r;
                char foundit;
            for(row = 0; row < 32; row++)  Mat[row] = Matrix[row];
            singular = 0;
            for(col = 0; col < 32; col++)
            {
                // Try to find a "1" in this column
                foundit = 0;
                for(row = col; row < 32; row++)
                {
                    if(Mat[row] & (1L<<col))
                    {
                        foundit = 1;
                        // Interchange rows to put this "1"
                        // on the diagonal
                        t = Mat[row];
                        Mat[row] = Mat[col];
                        Mat[col] = t;
                        // XOR the "1" into all later rows that
                        // have a "1" in this column
                        for(r=col+1; r<32; r++)
                        {
                            if(Mat[r] & (1L<<col))
                                Mat[r] ^= Mat[col];
                        }
                        row = 77;    // force exit from for loop
                    }
                }
                if(foundit==0)
                {
                    singular = 1;
                }
            }
        }
        printf(singular? "Singular" : "OK");
        printf("  Press ENTER ");  getchar();
    }
    printf("\r\nMatrix found is ");  printmatrix(Matrix);
    printf("\r\nCanonical form is "); printmatrix(Mat);

    printf("\r\n Applying the non-singular matrix to Ftab..\r\n");
    for(ki=0; ki<1024; ki++)    // for each element in Ftab
    {
            int r,c;
            UINT_32bits z;
        z = 0;
        for(r=0; r<32; r++)        // Matrix multiplication
        {
            if(ParityIsOdd( Ftab[ki] & Matrix[r] ))
                z |= (1L << r);
        }
        Ftab[ki] = z;
    }
    printf("\r\nWriting Ftab[] to the file FTAB.DAT..");
    {
            FILE *fp;
        fp = fopen("FTAB.DAT","w");
        if(fp)
        {
            fprintf(fp," ");
            for(i=0; i<1024; i++)
            {
                fprintf(fp,"0x%08lx,",Ftab[i]);
                if((i%6)==5) fprintf(fp,"\n ");
            }
        }
    }
}

ParityIsOdd( UINT_32bits x )
{
        int c;
        UINT_32bits s;
    s = 0;
    for(c=0; c<32; c++)
        s ^= (x >> c);
    return s & 1;
}

printmatrix( UINT_32bits *M )
{
        int i,j;
    for(i=0; i<16; i++)
    {
        printf("\r\n");
        for(j=0; j<32; j++)  printf((M[i] & (1L<<j))? "1" : "0");
        printf(" ");
        for(j=0; j<32; j++)  printf((M[i+16] & (1L<<j))? "1" : "0");
    }
    printf("\r\nPress ENTER...");
    getchar();
}
