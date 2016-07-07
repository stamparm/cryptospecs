/*
* MacGuffin Cipher
* 10/3/94 - Matt Blaze
* (fast, unrolled version)
*/
#define ROUNDS 32
#define KSIZE (ROUNDS*3)
/* expanded key structure */
typedef struct mcg_key {
unsigned short val[KSIZE];
} mcg_key;
#define TSIZE (1<<16)
/* the 8 s-boxes, expanded to put the output bits in the right
* places. note that these are the des s-boxes (in left-right,
* not canonical, order), but with only the "outer" two output
* bits. */
unsigned short sboxes[8][64] = {
/* 0 (S1) */
{0x0002, 0x0000, 0x0000, 0x0003, 0x0003, 0x0001, 0x0001, 0x0000,
0x0000, 0x0002, 0x0003, 0x0000, 0x0003, 0x0003, 0x0002, 0x0001,
0x0001, 0x0002, 0x0002, 0x0000, 0x0000, 0x0002, 0x0002, 0x0003,
0x0001, 0x0003, 0x0003, 0x0001, 0x0000, 0x0001, 0x0001, 0x0002,
0x0000, 0x0003, 0x0001, 0x0002, 0x0002, 0x0002, 0x0002, 0x0000,
0x0003, 0x0000, 0x0000, 0x0003, 0x0000, 0x0001, 0x0003, 0x0001,
0x0003, 0x0001, 0x0002, 0x0003, 0x0003, 0x0001, 0x0001, 0x0002,
0x0001, 0x0002, 0x0002, 0x0000, 0x0001, 0x0000, 0x0000, 0x0003},
/* 1 (S2) */
{0x000c, 0x0004, 0x0004, 0x000c, 0x0008, 0x0000, 0x0008, 0x0004,
0x0000, 0x000c, 0x000c, 0x0000, 0x0004, 0x0008, 0x0000, 0x0008,
0x000c, 0x0008, 0x0004, 0x0000, 0x0000, 0x0004, 0x000c, 0x0008,
0x0008, 0x0000, 0x0000, 0x000c, 0x0004, 0x000c, 0x0008, 0x0004,
0x0000, 0x000c, 0x0008, 0x0008, 0x0004, 0x0008, 0x000c, 0x0004,
0x0008, 0x0004, 0x0000, 0x000c, 0x000c, 0x0000, 0x0004, 0x0000,
0x0004, 0x000c, 0x0008, 0x0000, 0x0008, 0x0004, 0x0000, 0x0008,
0x000c, 0x0000, 0x0004, 0x0004, 0x0000, 0x0008, 0x000c, 0x000c},
/* 2 (S3) */
{0x0020, 0x0030, 0x0000, 0x0010, 0x0030, 0x0000, 0x0020, 0x0030,
0x0000, 0x0010, 0x0010, 0x0000, 0x0030, 0x0000, 0x0010, 0x0020,
0x0010, 0x0000, 0x0030, 0x0020, 0x0020, 0x0010, 0x0010, 0x0020,
0x0030, 0x0020, 0x0000, 0x0030, 0x0000, 0x0030, 0x0020, 0x0010,
0x0030, 0x0010, 0x0000, 0x0020, 0x0000, 0x0030, 0x0030, 0x0000,
0x0020, 0x0000, 0x0030, 0x0030, 0x0010, 0x0020, 0x0000, 0x0010,
0x0030, 0x0000, 0x0010, 0x0030, 0x0000, 0x0020, 0x0020, 0x0010,
0x0010, 0x0030, 0x0020, 0x0010, 0x0020, 0x0000, 0x0010, 0x0020},
/* 3 (S4) */
{0x0040, 0x00c0, 0x00c0, 0x0080, 0x0080, 0x00c0, 0x0040, 0x0040,
0x0000, 0x0000, 0x0000, 0x00c0, 0x00c0, 0x0000, 0x0080, 0x0040,
0x0040, 0x0000, 0x0000, 0x0040, 0x0080, 0x0000, 0x0040, 0x0080,
0x00c0, 0x0040, 0x0080, 0x0080, 0x0000, 0x0080, 0x00c0, 0x00c0,
0x0080, 0x0040, 0x0000, 0x00c0, 0x00c0, 0x0000, 0x0000, 0x0000,
0x0080, 0x0080, 0x00c0, 0x0040, 0x0040, 0x00c0, 0x00c0, 0x0080,
0x00c0, 0x00c0, 0x0040, 0x0000, 0x0040, 0x0040, 0x0080, 0x00c0,
0x0040, 0x0080, 0x0000, 0x0040, 0x0080, 0x0000, 0x0000, 0x0080},
/* 4 (S5) */
{0x0000, 0x0200, 0x0200, 0x0300, 0x0000, 0x0000, 0x0100, 0x0200,
0x0100, 0x0000, 0x0200, 0x0100, 0x0300, 0x0300, 0x0000, 0x0100,
0x0200, 0x0100, 0x0100, 0x0000, 0x0100, 0x0300, 0x0300, 0x0200,
0x0300, 0x0100, 0x0000, 0x0300, 0x0200, 0x0200, 0x0300, 0x0000,
0x0000, 0x0300, 0x0000, 0x0200, 0x0100, 0x0200, 0x0300, 0x0100,
0x0200, 0x0100, 0x0300, 0x0200, 0x0100, 0x0000, 0x0200, 0x0300,
0x0300, 0x0000, 0x0300, 0x0300, 0x0200, 0x0000, 0x0100, 0x0300,
0x0000, 0x0200, 0x0100, 0x0000, 0x0000, 0x0100, 0x0200, 0x0100},
/* 5 (S6) */
{0x0800, 0x0800, 0x0400, 0x0c00, 0x0800, 0x0000, 0x0c00, 0x0000,
0x0c00, 0x0400, 0x0000, 0x0800, 0x0000, 0x0c00, 0x0800, 0x0400,
0x0000, 0x0000, 0x0c00, 0x0400, 0x0400, 0x0c00, 0x0000, 0x0800,
0x0800, 0x0000, 0x0400, 0x0c00, 0x0400, 0x0400, 0x0c00, 0x0800,
0x0c00, 0x0000, 0x0800, 0x0400, 0x0c00, 0x0000, 0x0400, 0x0800,
0x0000, 0x0c00, 0x0800, 0x0400, 0x0800, 0x0c00, 0x0400, 0x0800,
0x0400, 0x0c00, 0x0000, 0x0800, 0x0000, 0x0400, 0x0800, 0x0400,
0x0400, 0x0000, 0x0c00, 0x0000, 0x0c00, 0x0800, 0x0000, 0x0c00},
/* 6 (S7) */
{0x0000, 0x3000, 0x3000, 0x0000, 0x0000, 0x3000, 0x2000, 0x1000,
0x3000, 0x0000, 0x0000, 0x3000, 0x2000, 0x1000, 0x3000, 0x2000,
0x1000, 0x2000, 0x2000, 0x1000, 0x3000, 0x1000, 0x1000, 0x2000,
0x1000, 0x0000, 0x2000, 0x3000, 0x0000, 0x2000, 0x1000, 0x0000,
0x1000, 0x0000, 0x0000, 0x3000, 0x3000, 0x3000, 0x3000, 0x2000,
0x2000, 0x1000, 0x1000, 0x0000, 0x1000, 0x2000, 0x2000, 0x1000,
0x2000, 0x3000, 0x3000, 0x1000, 0x0000, 0x0000, 0x2000, 0x3000,
0x0000, 0x2000, 0x1000, 0x0000, 0x3000, 0x1000, 0x0000, 0x2000},
/* 7 (S8) */
{0xc000, 0x4000, 0x0000, 0xc000, 0x8000, 0xc000, 0x0000, 0x8000,
0x0000, 0x8000, 0xc000, 0x4000, 0xc000, 0x4000, 0x4000, 0x0000,
0x8000, 0x8000, 0xc000, 0x4000, 0x4000, 0x0000, 0x8000, 0xc000,
0x4000, 0x0000, 0x0000, 0x8000, 0x8000, 0xc000, 0x4000, 0x0000,
0x4000, 0x0000, 0xc000, 0x4000, 0x0000, 0x8000, 0x4000, 0x4000,
0xc000, 0x0000, 0x8000, 0x8000, 0x8000, 0x8000, 0x0000, 0xc000,
0x0000, 0xc000, 0x0000, 0x8000, 0x8000, 0xc000, 0xc000, 0x0000,
0xc000, 0x4000, 0x4000, 0x4000, 0x4000, 0x0000, 0x8000, 0xc000}
};
/* table of s-box outputs, expanded for 16 bit input.
* this one table includes all 8 sboxes - just mask off
* the output bits not in use. */
unsigned short stable[TSIZE];
/* we exploit two features of the s-box input & output perms -
* first, each s-box uses as input two different bits from each
* of the three registers in the right side, and, second,
* for each s-box there is another-sbox with no common input bits
* between them. therefore we can lookup two s-box outputs in one
* probe of the table. just mask off the approprate input bits
* in the table below for each of the three registers and OR
* together for the table lookup index.
* these masks are also available below in #defines, for better
* lookup speed in unrolled loops. */
unsigned short lookupmasks[4][3] = {
/*a , b , c */
{0x0036, 0x06c0, 0x6900}, /* s1+s2 */
{0x5048, 0x2106, 0x8411}, /* s3+s4 */
{0x8601, 0x4828, 0x10c4}, /* s5+s7 */
{0x2980, 0x9011, 0x022a}}; /* s6+s8 */
/* this table contains the corresponding output masks for the
* lookup procedure mentioned above.
* (similarly available below in #defines). */
unsigned short outputmasks[4] = {
0x000f /*s1+s2*/, 0x00f0 /*s3+s4*/,
0x3300 /*s5+s7*/, 0xcc00 /*s6+s8*/};
/* input and output lookup masks (see above) */
/* s1+s2 */
#define IN00 0x0036
#define IN01 0x06c0
#define IN02 0x6900
#define OUT0 0x000f
/* s3+s4 */
#define IN10 0x5048
#define IN11 0x2106
#define IN12 0x8411
#define OUT1 0x00f0
/* s5+s7 */
#define IN20 0x8601
#define IN21 0x4828
#define IN22 0x10c4
#define OUT2 0x3300
/* s6+s8 */
#define IN30 0x2980
#define IN31 0x9011
#define IN32 0x022a
#define OUT3 0xcc00
/*
* initialize the macguffin s-box tables.
* this takes a while, but is only done once.
*/
mcg_init()
{
unsigned int i,j,k;
int b;
/*
* input permutation for the 8 s-boxes.
* each row entry is a bit position from
* one of the three right hand registers,
* as follows:
* a,a,b,b,c,c
*/
static int sbits[8][6] = {
{2,5,6,9,11,13}, {1,4,7,10,8,14},
{3,6,8,13,0,15}, {12,14,1,2,4,10},
{0,10,3,14,6,12}, {7,8,12,15,1,5},
{9,15,5,11,2,7}, {11,13,0,4,3,9}};
for (i=0; i<TSIZE; i++) {
stable[i]=0;
for (j=0; j<8; j++)
stable[i] |=
sboxes[j][((i>>sbits[j][0])&1)
|(((i>>sbits[j][1])&1)<<1)
|(((i>>sbits[j][2])&1)<<2)
|(((i>>sbits[j][3])&1)<<3)
|(((i>>sbits[j][4])&1)<<4)
|(((i>>sbits[j][5])&1)<<5)];
}
}
#define OUT1 0x00f0
/* s5+s7 */
#define IN20 0x8601
#define IN21 0x4828
#define IN22 0x10c4
#define OUT2 0x3300
/* s6+s8 */
#define IN30 0x2980
#define IN31 0x9011
#define IN32 0x022a
#define OUT3 0xcc00
/*
* initialize the macguffin s-box tables.
* this takes a while, but is only done once.
*/
mcg_init()
{
unsigned int i,j,k;
int b;
/*
* input permutation for the 8 s-boxes.
* each row entry is a bit position from
* one of the three right hand registers,
* as follows:
* a,a,b,b,c,c
*/
static int sbits[8][6] = {
{2,5,6,9,11,13}, {1,4,7,10,8,14},
{3,6,8,13,0,15}, {12,14,1,2,4,10},
{0,10,3,14,6,12}, {7,8,12,15,1,5},
{9,15,5,11,2,7}, {11,13,0,4,3,9}};
for (i=0; i<TSIZE; i++) {
stable[i]=0;
for (j=0; j<8; j++)
stable[i] |=
sboxes[j][((i>>sbits[j][0])&1)
|(((i>>sbits[j][1])&1)<<1)
|(((i>>sbits[j][2])&1)<<2)
|(((i>>sbits[j][3])&1)<<3)
|(((i>>sbits[j][4])&1)<<4)
|(((i>>sbits[j][5])&1)<<5)];
}
}
/*
* expand key to ek
*/
mcg_keyset(key,ek)
unsigned char *key;
mcg_key *ek;
{
int i,j;
unsigned char k[2][8];
mcg_init();
bcopy(&key[0],k[0],8);
bcopy(&key[8],k[1],8);
for (i=0; i<KSIZE; i++)
ek->val[i]=0;
for (i=0; i<2; i++)
for (j=0; j<32; j++) {
mcg_block_encrypt(k[i],ek);
ek->val[j*3] ^= k[i][0] | (k[i][1]<<8);
ek->val[j*3+1] ^= k[i][2] | (k[i][3]<<8);
ek->val[j*3+2] ^= k[i][4] | (k[i][5]<<8);
}
}
/*
* codebook encrypt one block with given expanded key
*/
mcg_block_encrypt(blk,key)
unsigned char *blk;
mcg_key *key;
{
unsigned short r0, r1, r2, r3, a, b, c;
int i;
unsigned short *ek;
/* copy cleartext into local words */
r0=blk[0]|(blk[1]<<8);
r1=blk[2]|(blk[3]<<8);
r2=blk[4]|(blk[5]<<8);
r3=blk[6]|(blk[7]<<8);
ek = &(key->val[0]);
/* round loop, unrolled 4x */
for (i=0; i<(ROUNDS/4); i++) {
a = r1 ^ *(ek++); b = r2 ^ *(ek++); c = r3 ^ *(ek++);
r0 ^=((OUT0 & stable[(a & IN00)|(b & IN01)|(c & IN02)])
| (OUT1 & stable[(a & IN10)|(b & IN11)|(c & IN12)])
| (OUT2 & stable[(a & IN20)|(b & IN21)|(c & IN22)])
| (OUT3 & stable[(a & IN30)|(b & IN31)|(c & IN32)]));
a = r2 ^ *(ek++); b = r3 ^ *(ek++); c = r0 ^ *(ek++);
r1 ^=((OUT0 & stable[(a & IN00)|(b & IN01)|(c & IN02)])
| (OUT1 & stable[(a & IN10)|(b & IN11)|(c & IN12)])
| (OUT2 & stable[(a & IN20)|(b & IN21)|(c & IN22)])
| (OUT3 & stable[(a & IN30)|(b & IN31)|(c & IN32)]));
a = r3 ^ *(ek++); b = r0 ^ *(ek++); c = r1 ^ *(ek++);
r2 ^=((OUT0 & stable[(a & IN00)|(b & IN01)|(c & IN02)])
| (OUT1 & stable[(a & IN10)|(b & IN11)|(c & IN12)])
| (OUT2 & stable[(a & IN20)|(b & IN21)|(c & IN22)])
| (OUT3 & stable[(a & IN30)|(b & IN31)|(c & IN32)]));
a = r0 ^ *(ek++); b = r1 ^ *(ek++); c = r2 ^ *(ek++);
r3 ^=((OUT0 & stable[(a & IN00)|(b & IN01)|(c & IN02)])
| (OUT1 & stable[(a & IN10)|(b & IN11)|(c & IN12)])
| (OUT2 & stable[(a & IN20)|(b & IN21)|(c & IN22)])
| (OUT3 & stable[(a & IN30)|(b & IN31)|(c & IN32)]));
}
/* copy 4 encrypted words back to output */
blk[0] = r0; blk[1] = r0>>8;
blk[2] = r1; blk[3] = r1>>8;
blk[4] = r2; blk[5] = r2>>8;
blk[6] = r3; blk[7] = r3>>8;
}
/*
* codebook decrypt one block with given expanded key
*/
mcg_block_decrypt(blk,key)
unsigned char *blk;
mcg_key *key;
{
unsigned short r0, r1, r2, r3, a, b, c;
int i;
unsigned short *ek;
/* copy ciphertext to 4 local words */
r0=blk[0]|(blk[1]<<8);
r1=blk[2]|(blk[3]<<8);
r2=blk[4]|(blk[5]<<8);
r3=blk[6]|(blk[7]<<8);
ek = &(key->val[KSIZE]);
/* round loop, unrolled 4x */
for (i=0; i<(ROUNDS/4); ++i) {
c = r2 ^ *(--ek); b = r1 ^ *(--ek); a = r0 ^ *(--ek);
r3 ^=((OUT0 & stable[(a & IN00)|(b & IN01)|(c & IN02)])
| (OUT1 & stable[(a & IN10)|(b & IN11)|(c & IN12)])
| (OUT2 & stable[(a & IN20)|(b & IN21)|(c & IN22)])
| (OUT3 & stable[(a & IN30)|(b & IN31)|(c & IN32)]));
c = r1 ^ *(--ek); b = r0 ^ *(--ek); a = r3 ^ *(--ek);
r2 ^=((OUT0 & stable[(a & IN00)|(b & IN01)|(c & IN02)])
| (OUT1 & stable[(a & IN10)|(b & IN11)|(c & IN12)])
| (OUT2 & stable[(a & IN20)|(b & IN21)|(c & IN22)])
| (OUT3 & stable[(a & IN30)|(b & IN31)|(c & IN32)]));
c = r0 ^ *(--ek); b = r3 ^ *(--ek); a = r2 ^ *(--ek);
r1 ^=((OUT0 & stable[(a & IN00)|(b & IN01)|(c & IN02)])
| (OUT1 & stable[(a & IN10)|(b & IN11)|(c & IN12)])
| (OUT2 & stable[(a & IN20)|(b & IN21)|(c & IN22)])
| (OUT3 & stable[(a & IN30)|(b & IN31)|(c & IN32)]));
c = r3 ^ *(--ek); b = r2 ^ *(--ek); a = r1 ^ *(--ek);
r0 ^=((OUT0 & stable[(a & IN00)|(b & IN01)|(c & IN02)])
| (OUT1 & stable[(a & IN10)|(b & IN11)|(c & IN12)])
| (OUT2 & stable[(a & IN20)|(b & IN21)|(c & IN22)])
| (OUT3 & stable[(a & IN30)|(b & IN31)|(c & IN32)]));
}
/* copy decrypted bits back to output */
blk[0] = r0; blk[1] = r0>>8;
blk[2] = r1; blk[3] = r1>>8;
blk[4] = r2; blk[5] = r2>>8;
blk[6] = r3; blk[7] = r3>>8;
}