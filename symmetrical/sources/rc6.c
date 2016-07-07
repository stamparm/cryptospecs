
/* This is an independent implementation of the RC6 algorithm that  */
/* Ron Rivest and RSA Labs have submitted as a candidate for the    */
/* NIST AES activity.  Refer to RSA Labs and Ron Rivest for any     */
/* copyright, patent or license issues for the RC6 algorithm.       */
/*                                                                  */
/* Copyright in this implementation is held by Dr B R Gladman but   */
/* I hereby give permission for its free direct or derivative use   */
/* subject to acknowledgment of its origin and compliance with any  */
/* constraints that are placed on the exploitation of RC6 by its    */
/* designers.                                                       */
/*                                                                  */
/* Dr Brian Gladman (gladman@seven77.demon.co.uk) 18th July 1998    */
/*
   Timing data:

Algorithm: rc6 (rc6.c)
128 bit key:
Key Setup:    1584 cycles
Encrypt:       251 cycles =   102.0 mbits/sec
Decrypt:       239 cycles =   107.1 mbits/sec
Mean:          245 cycles =   104.5 mbits/sec
192 bit key:
Key Setup:    1877 cycles
Encrypt:       255 cycles =   100.5 mbits/sec
Decrypt:       248 cycles =   103.2 mbits/sec
Mean:          251 cycles =   101.9 mbits/sec
256 bit key:
Key Setup:    1779 cycles
Encrypt:       244 cycles =   104.8 mbits/sec
Decrypt:       239 cycles =   107.1 mbits/sec
Mean:          242 cycles =   105.9 mbits/sec

*/

#include "../std_defs.h"

static char *alg_name[] = { "rc6", "rc62.c" };

char **cipher_name()
{
    return alg_name;
}

#define f_rnd(i,a,b,c,d)                \
        t = b * (b + b + 1);            \
        u = d * (d + d + 1);            \
        a = rotl(a ^ rotl(t,5), u);     \
        c = rotl(c ^ rotl(u,5), t);     \
        a += l_key[i];                  \
        c += l_key[i + 1]               \

#define i_rnd(i,a,b,c,d)                   \
        u = rotl(d * (d + d + 1), 5);      \
        t = rotl(b * (b + b + 1), 5);      \
        c = rotr(c - l_key[i + 1], t) ^ u; \
        a = rotr(a - l_key[i], u) ^ t      \

u4byte  l_key[44];  /* storage for the key schedule         */

/* initialise the key schedule from the user supplied key   */

u4byte *set_key(const u4byte in_key[], const u4byte key_len)
{   u4byte  i, j, k, a, b, l[8], t;

    l_key[0] = 0xb7e15163;

    for(k = 1; k < 44; ++k)
        
        l_key[k] = l_key[k - 1] + 0x9e3779b9;

    for(k = 0; k < key_len / 32; ++k)

        l[k] = in_key[k];

    t = (key_len / 32) - 1;

    a = b = i = j = 0;

    for(k = 0; k < 132; ++k)
    {   a = rotl(l_key[i] + a + b, 3); b += a;
        b = rotl(l[j] + b, b);
        l_key[i] = a; l[j] = b;
        i = (i == 43 ? 0 : i + 1);
        j = (j == t ? 0 : j + 1);
    }

    return l_key;
};

/* encrypt a block of text  */

void encrypt(const u4byte in_blk[4], u4byte out_blk[4])
{   u4byte  a,b,c,d,t,u;

    a = in_blk[0]; b = in_blk[1] + l_key[0];
    c = in_blk[2]; d = in_blk[3] + l_key[1];

    f_rnd( 2,a,b,c,d); f_rnd( 4,b,c,d,a);
    f_rnd( 6,c,d,a,b); f_rnd( 8,d,a,b,c);
    f_rnd(10,a,b,c,d); f_rnd(12,b,c,d,a);
    f_rnd(14,c,d,a,b); f_rnd(16,d,a,b,c);
    f_rnd(18,a,b,c,d); f_rnd(20,b,c,d,a);
    f_rnd(22,c,d,a,b); f_rnd(24,d,a,b,c);
    f_rnd(26,a,b,c,d); f_rnd(28,b,c,d,a);
    f_rnd(30,c,d,a,b); f_rnd(32,d,a,b,c);
    f_rnd(34,a,b,c,d); f_rnd(36,b,c,d,a);
    f_rnd(38,c,d,a,b); f_rnd(40,d,a,b,c);

    out_blk[0] = a + l_key[42]; out_blk[1] = b;
    out_blk[2] = c + l_key[43]; out_blk[3] = d;
};

/* decrypt a block of text  */

void decrypt(const u4byte in_blk[4], u4byte out_blk[4])
{   u4byte  a,b,c,d,t,u;

    d = in_blk[3]; c = in_blk[2] - l_key[43]; 
    b = in_blk[1]; a = in_blk[0] - l_key[42];

    i_rnd(40,d,a,b,c); i_rnd(38,c,d,a,b);
    i_rnd(36,b,c,d,a); i_rnd(34,a,b,c,d);
    i_rnd(32,d,a,b,c); i_rnd(30,c,d,a,b);
    i_rnd(28,b,c,d,a); i_rnd(26,a,b,c,d);
    i_rnd(24,d,a,b,c); i_rnd(22,c,d,a,b);
    i_rnd(20,b,c,d,a); i_rnd(18,a,b,c,d);
    i_rnd(16,d,a,b,c); i_rnd(14,c,d,a,b);
    i_rnd(12,b,c,d,a); i_rnd(10,a,b,c,d);
    i_rnd( 8,d,a,b,c); i_rnd( 6,c,d,a,b);
    i_rnd( 4,b,c,d,a); i_rnd( 2,a,b,c,d);

    out_blk[3] = d - l_key[1]; out_blk[2] = c; 
    out_blk[1] = b - l_key[0]; out_blk[0] = a; 
};
