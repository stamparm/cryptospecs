/*******************************************************************************
*
* FILE:         crypton.c
*
* DESCRIPTION:  Optimized C implementation of Crypton version 0.7
*
* AUTHOR:       Chae Hoon Lim and Hyo Sun Hwang
*               E-mail: chlim@future.co.kr, hyosun@future.co.kr
*               http://crypt.future.co.kr/~chlim
*               Information and Communications Research Center, 
*               Future Systems, Inc.
*               372-2, Yang Jae-Dong, Seo Cho-Gu, Seoul, 137-130, KOREA
*               Tel: +82-2-578-0581 (ext. 557), Fax: +82-2-578-0584
*
* DATE:         July 10, 1998
*
* NOTE: This code is optimized for running on Pentium Pro using MS Visual 
*       C++ v5.0. It may not be optimal on other processors (in particular, 
*       on RISC processors).
*
*       This code contains 4 CRYPTON core functions (CryptonEncrypt, 
*       CryptonExpandKey, CryptonGenEncRoundKey and CryptonGenDecRoundkey).
*       They are called by AES API functions (aesapi.c).
*
*******************************************************************************/

#include "crypton.h"
#include "crypton.tab"

/*============= Definitions for Encryption/Decryption =============*/

/* byte extracting/positioning from/into DWORD */
#ifdef BIG_ENDIAN
    #define GetByte0(A)  ( (BYTE)((A)>>24) )    /* A: DWORD */
    #define GetByte1(A)  ( (BYTE)((A)>>16) )
    #define GetByte2(A)  ( (BYTE)((A)>> 8) )
    #define GetByte3(A)  ( (BYTE)((A)    ) )

    #define PutByte0(B)  ( (DWORD)(B)<<24 )     /* B: BYTE */
    #define PutByte1(B)  ( (DWORD)(B)<<16 )
    #define PutByte2(B)  ( (DWORD)(B)<< 8 )
    #define PutByte3(B)  ( (DWORD)(B)     )
#else
    #define GetByte0(A)  ( (BYTE)((A)    ) )    /* A: DWORD */
    #define GetByte1(A)  ( (BYTE)((A)>> 8) )
    #define GetByte2(A)  ( (BYTE)((A)>>16) )
    #define GetByte3(A)  ( (BYTE)((A)>>24) )

    #define PutByte0(B)  ( (DWORD)(B)     )     /* B: BYTE */
    #define PutByte1(B)  ( (DWORD)(B)<< 8 )
    #define PutByte2(B)  ( (DWORD)(B)<<16 )
    #define PutByte3(B)  ( (DWORD)(B)<<24 )
#endif


/* Round transformation for odd rounds */
#define CryptonRound0(A, B, C, D, E, F, G, H, K) {      \
    A  = SS0[GetByte0(E)] ^ SS1[GetByte0(F)];           \
    B  = SS1[GetByte1(E)] ^ SS2[GetByte1(F)];           \
    C  = SS2[GetByte2(E)] ^ SS3[GetByte2(F)];           \
    D  = SS3[GetByte3(E)] ^ SS0[GetByte3(F)];           \
    A ^= SS2[GetByte0(G)] ^ SS3[GetByte0(H)] ^ (K)[0];  \
    B ^= SS3[GetByte1(G)] ^ SS0[GetByte1(H)] ^ (K)[1];  \
    C ^= SS0[GetByte2(G)] ^ SS1[GetByte2(H)] ^ (K)[2];  \
    D ^= SS1[GetByte3(G)] ^ SS2[GetByte3(H)] ^ (K)[3];  \
}

/* Round transformation for even rounds */
#define CryptonRound1(A, B, C, D, E, F, G, H, K) {      \
    A  = SS2[GetByte0(E)] ^ SS3[GetByte0(F)];           \
    B  = SS3[GetByte1(E)] ^ SS0[GetByte1(F)];           \
    C  = SS0[GetByte2(E)] ^ SS1[GetByte2(F)];           \
    D  = SS1[GetByte3(E)] ^ SS2[GetByte3(F)];           \
    A ^= SS0[GetByte0(G)] ^ SS1[GetByte0(H)] ^ (K)[0];  \
    B ^= SS1[GetByte1(G)] ^ SS2[GetByte1(H)] ^ (K)[1];  \
    C ^= SS2[GetByte2(G)] ^ SS3[GetByte2(H)] ^ (K)[2];  \
    D ^= SS3[GetByte3(G)] ^ SS0[GetByte3(H)] ^ (K)[3];  \
}
/*
    CryptonRound1(A, B, C, D, E, F, G, H, K) exactly equals
    CryptonRound0(A, B, C, D, G, H, E, F, K)
*/


#define FINAL_ROUND_TYPE  1

/* special final round */
#if FINAL_ROUND_TYPE == 1     /* faster on PCs */
#define CryptonFinalR(pb, A, B, C, D, K) {          \
    pb[ 0] = S2[GetByte0(A)] ^ GetByte0((K)[0]);    \
    pb[ 1] = S3[GetByte0(B)] ^ GetByte1((K)[0]);    \
    pb[ 4] = S3[GetByte1(A)] ^ GetByte0((K)[1]);    \
    pb[ 5] = S0[GetByte1(B)] ^ GetByte1((K)[1]);    \
    pb[ 8] = S0[GetByte2(A)] ^ GetByte0((K)[2]);    \
    pb[ 9] = S1[GetByte2(B)] ^ GetByte1((K)[2]);    \
    pb[12] = S1[GetByte3(A)] ^ GetByte0((K)[3]);    \
    pb[13] = S2[GetByte3(B)] ^ GetByte1((K)[3]);    \
    pb[ 2] = S0[GetByte0(C)] ^ GetByte2((K)[0]);    \
    pb[ 3] = S1[GetByte0(D)] ^ GetByte3((K)[0]);    \
    pb[ 6] = S1[GetByte1(C)] ^ GetByte2((K)[1]);    \
    pb[ 7] = S2[GetByte1(D)] ^ GetByte3((K)[1]);    \
    pb[10] = S2[GetByte2(C)] ^ GetByte2((K)[2]);    \
    pb[11] = S3[GetByte2(D)] ^ GetByte3((K)[2]);    \
    pb[14] = S3[GetByte3(C)] ^ GetByte2((K)[3]);    \
    pb[15] = S0[GetByte3(D)] ^ GetByte3((K)[3]);    \
}

#elif FINAL_ROUND_TYPE == 2     /* faster on RISC processors */
#define CryptonFinalR(pb, A, B, C, D, K) {          \
    DWORD *pdw = (DWORD *)pb;                       \
    (pdw)[0] = PutByte0(S2[GetByte0(A)]) ^          \
               PutByte1(S3[GetByte0(B)]) ^          \
               PutByte2(S0[GetByte0(C)]) ^          \
               PutByte3(S1[GetByte0(D)]) ^ (K)[0];  \
    (pdw)[1] = PutByte0(S3[GetByte1(A)]) ^          \
               PutByte1(S0[GetByte1(B)]) ^          \
               PutByte2(S1[GetByte1(C)]) ^          \
               PutByte3(S2[GetByte1(D)]) ^ (K)[1];  \
    (pdw)[2] = PutByte0(S0[GetByte2(A)]) ^          \
               PutByte1(S1[GetByte2(B)]) ^          \
               PutByte2(S2[GetByte2(C)]) ^          \
               PutByte3(S3[GetByte2(D)]) ^ (K)[2];  \
    (pdw)[3] = PutByte0(S1[GetByte3(A)]) ^          \
               PutByte1(S2[GetByte3(B)]) ^          \
               PutByte2(S3[GetByte3(C)]) ^          \
               PutByte3(S0[GetByte3(D)]) ^ (K)[3];  \
}
#endif


/* save inter-round values */
#if defined(CheckInterValue)
    extern BYTE pdwInterVal[NoRounds+1][CryptonBlockSize];
    extern int PRN;
    #define INTER_VALUE_OUT(A, B, C, D, N) {    \
        if(PRN) {                               \
            DWORD temp[4];                      \
            temp[0] = A;                        \
            temp[1] = B;                        \
            temp[2] = C;                        \
            temp[3] = D;                        \
            memcpy(pdwInterVal[N], (BYTE *)temp, CryptonBlockSize); \
        }                                       \
    }
#else
    #define INTER_VALUE_OUT(A, B, C, D, N)
#endif


/*######################## Block Encrypt/Decrypt #########################*/

/* encrypton or decryption, depending on RoundKeys */
#if defined(USE_ASM)
    #include "cryp_asm.c"
#else

void CryptonEncrypt(pbData, pdwRoundKey)
BYTE *pbData;
DWORD *pdwRoundKey;
{
    DWORD A, B, C, D, E, F, G, H, *K=pdwRoundKey;

    E = ((DWORD *)pbData)[0] ^ K[0];
    F = ((DWORD *)pbData)[1] ^ K[1];
    G = ((DWORD *)pbData)[2] ^ K[2];
    H = ((DWORD *)pbData)[3] ^ K[3];
    INTER_VALUE_OUT(E, F, G, H, 0);

    CryptonRound0(A, B, C, D, E, F, G, H, K+ 4);    /*  1 */
    INTER_VALUE_OUT(A, B, C, D, 1);
    CryptonRound1(E, F, G, H, A, B, C, D, K+ 8);    /*  2 */
    INTER_VALUE_OUT(E, F, G, H, 2);
    CryptonRound0(A, B, C, D, E, F, G, H, K+12);    /*  3 */
    INTER_VALUE_OUT(A, B, C, D, 3);
    CryptonRound1(E, F, G, H, A, B, C, D, K+16);    /*  4 */
    INTER_VALUE_OUT(E, F, G, H, 4);
    CryptonRound0(A, B, C, D, E, F, G, H, K+20);    /*  5 */
    INTER_VALUE_OUT(A, B, C, D, 5);
    CryptonRound1(E, F, G, H, A, B, C, D, K+24);    /*  6 */
    INTER_VALUE_OUT(E, F, G, H, 6);
    CryptonRound0(A, B, C, D, E, F, G, H, K+28);    /*  7 */
    INTER_VALUE_OUT(A, B, C, D, 7);
    CryptonRound1(E, F, G, H, A, B, C, D, K+32);    /*  8 */
    INTER_VALUE_OUT(E, F, G, H, 8);
    CryptonRound0(A, B, C, D, E, F, G, H, K+36);    /*  9 */
    INTER_VALUE_OUT(A, B, C, D, 9);
    CryptonRound1(E, F, G, H, A, B, C, D, K+40);    /* 10 */
    INTER_VALUE_OUT(E, F, G, H,10);
    CryptonRound0(A, B, C, D, E, F, G, H, K+44);    /* 11 */
    INTER_VALUE_OUT(A, B, C, D,11);
    CryptonFinalR(pbData, A, B, C, D, K+48);        /* 12 */
    INTER_VALUE_OUT(((DWORD *)pbData)[0], ((DWORD *)pbData)[1], \
                    ((DWORD *)pbData)[2], ((DWORD *)pbData)[3], 12);
}
#endif

/******************************************************************************/


/*================ Definitions for key Expansion =================*/

/* Masking words used for bit permutation */
#ifdef BIG_ENDIAN /* byte-reversed versions */
    #define MW0     0xfcf3cf3f
    #define MW1     0xf3cf3ffc
    #define MW2     0xcf3ffcf3
    #define MW3     0x3ffcf3cf
#else
    #define MW0     0x3fcff3fc
    #define MW1     0xfc3fcff3
    #define MW2     0xf3fc3fcf
    #define MW3     0xcff3fc3f
#endif


#define SBOX_TRANS_TYPE     1

#if SBOX_TRANS_TYPE == 1        /* faster on PCs */
#define SboxTrans0(pb, A, B, C, D) {    \
    (pb)[ 0] = S0[GetByte0(A)];         \
    (pb)[ 1] = S1[GetByte0(B)];         \
    (pb)[ 4] = S1[GetByte1(A)];         \
    (pb)[ 5] = S2[GetByte1(B)];         \
    (pb)[ 8] = S2[GetByte2(A)];         \
    (pb)[ 9] = S3[GetByte2(B)];         \
    (pb)[12] = S3[GetByte3(A)];         \
    (pb)[13] = S0[GetByte3(B)];         \
    (pb)[ 2] = S2[GetByte0(C)];         \
    (pb)[ 3] = S3[GetByte0(D)];         \
    (pb)[ 6] = S3[GetByte1(C)];         \
    (pb)[ 7] = S0[GetByte1(D)];         \
    (pb)[10] = S0[GetByte2(C)];         \
    (pb)[11] = S1[GetByte2(D)];         \
    (pb)[14] = S1[GetByte3(C)];         \
    (pb)[15] = S2[GetByte3(D)];         \
}

#define SboxTrans1(pb, A, B, C, D) {    \
    (pb)[ 0] = S2[GetByte0(A)];         \
    (pb)[ 1] = S3[GetByte0(B)];         \
    (pb)[ 4] = S3[GetByte1(A)];         \
    (pb)[ 5] = S0[GetByte1(B)];         \
    (pb)[ 8] = S0[GetByte2(A)];         \
    (pb)[ 9] = S1[GetByte2(B)];         \
    (pb)[12] = S1[GetByte3(A)];         \
    (pb)[13] = S2[GetByte3(B)];         \
    (pb)[ 2] = S0[GetByte0(C)];         \
    (pb)[ 3] = S1[GetByte0(D)];         \
    (pb)[ 6] = S1[GetByte1(C)];         \
    (pb)[ 7] = S2[GetByte1(D)];         \
    (pb)[10] = S2[GetByte2(C)];         \
    (pb)[11] = S3[GetByte2(D)];         \
    (pb)[14] = S3[GetByte3(C)];         \
    (pb)[15] = S0[GetByte3(D)];         \
}

#elif SBOX_TRANS_TYPE ==2      /* faster on RISCs */
#define SboxTrans0(pb, A, B, C, D) {        \
    DWORD *pdw = (DWORD *)(pb);             \
    (pdw)[0] = PutByte0(S0[GetByte0(A)]) ^  \
               PutByte1(S1[GetByte0(B)]) ^  \
               PutByte2(S2[GetByte0(C)]) ^  \
               PutByte3(S3[GetByte0(D)]);   \
    (pdw)[1] = PutByte0(S1[GetByte1(A)]) ^  \
               PutByte1(S2[GetByte1(B)]) ^  \
               PutByte2(S3[GetByte1(C)]) ^  \
               PutByte3(S0[GetByte1(D)]);   \
    (pdw)[2] = PutByte0(S2[GetByte2(A)]) ^  \
               PutByte1(S3[GetByte2(B)]) ^  \
               PutByte2(S0[GetByte2(C)]) ^  \
               PutByte3(S1[GetByte2(D)]);   \
    (pdw)[3] = PutByte0(S3[GetByte3(A)]) ^  \
               PutByte1(S0[GetByte3(B)]) ^  \
               PutByte2(S1[GetByte3(C)]) ^  \
               PutByte3(S2[GetByte3(D)]);   \
}

#define SboxTrans1(pb, A, B, C, D) {        \
    DWORD *pdw = (DWORD *)(pb);             \
    (pdw)[0] = PutByte0(S2[GetByte0(A)]) ^  \
               PutByte1(S3[GetByte0(B)]) ^  \
               PutByte2(S0[GetByte0(C)]) ^  \
               PutByte3(S1[GetByte0(D)]);   \
    (pdw)[1] = PutByte0(S3[GetByte1(A)]) ^  \
               PutByte1(S0[GetByte1(B)]) ^  \
               PutByte2(S1[GetByte1(C)]) ^  \
               PutByte3(S2[GetByte1(D)]);   \
    (pdw)[2] = PutByte0(S0[GetByte2(A)]) ^  \
               PutByte1(S1[GetByte2(B)]) ^  \
               PutByte2(S2[GetByte2(C)]) ^  \
               PutByte3(S3[GetByte2(D)]);   \
    (pdw)[3] = PutByte0(S1[GetByte3(A)]) ^  \
               PutByte1(S2[GetByte3(B)]) ^  \
               PutByte2(S3[GetByte3(C)]) ^  \
               PutByte3(S0[GetByte3(D)]);   \
}
#endif


/* Key expansion: Bit permutation, constant addition,
   substitution and byte transposition */
#define KeyExpand0(pb, E, F, G, H,  K0, K1, K2, K3) {       \
    register DWORD A, B, C, D;                              \
    A = (E & MW0) ^ (F & MW1) ^ (G & MW2) ^ (H & MW3) ^ K0; \
    B = (E & MW1) ^ (F & MW2) ^ (G & MW3) ^ (H & MW0) ^ K1; \
    C = (E & MW2) ^ (F & MW3) ^ (G & MW0) ^ (H & MW1) ^ K2; \
    D = (E & MW3) ^ (F & MW0) ^ (G & MW1) ^ (H & MW2) ^ K3; \
    SboxTrans0(pb, A, B, C, D);                             \
}

#define KeyExpand1(pb, E, F, G, H, K0, K1, K2, K3) {        \
    register DWORD A, B, C, D;                              \
    A = (E & MW2) ^ (F & MW3) ^ (G & MW0) ^ (H & MW1) ^ K0; \
    B = (E & MW3) ^ (F & MW0) ^ (G & MW1) ^ (H & MW2) ^ K1; \
    C = (E & MW0) ^ (F & MW1) ^ (G & MW2) ^ (H & MW3) ^ K2; \
    D = (E & MW1) ^ (F & MW2) ^ (G & MW3) ^ (H & MW0) ^ K3; \
    SboxTrans1(pb, A, B, C, D);                             \
}


/* Constants for key expansion */
#ifdef BIG_ENDIAN      /* byte-reversed versions */
    #define  C0  0x85ae67bb
    #define  C1  0x72f36e3c
    #define  C2  0x3af54fa5
    #define  C3  0x7f520e51
    #define  C4  0x8c68059b
    #define  C5  0xabd9831f
    #define  C6  0x19cde05b
    #define  C7  0x5d9dbbcb
#else
    #define  C0  0xbb67ae85
    #define  C1  0x3c6ef372
    #define  C2  0xa54ff53a
    #define  C3  0x510e527f
    #define  C4  0x9b05688c
    #define  C5  0x1f83d9ab
    #define  C6  0x5be0cd19
    #define  C7  0xcbbb9d5d
#endif

/*######################### Expand a User Key ########################*/

/* Generate 8 Expanded keys from a user-supplied key */

void CryptonExpandKey(pdwExpKey, pbUserKey, dwUserKeyLen)
DWORD *pdwExpKey;
BYTE *pbUserKey;
int dwUserKeyLen;
{
    BYTE pbTemp[32], *pbEK = (BYTE *)pdwExpKey;
    DWORD E, F, G, H, Sum, *pdwEK;

    BlockSet(pbTemp, 0);
    BlockSet(pbTemp+16, 0);
    memcpy(pbTemp, pbUserKey, dwUserKeyLen);
    pdwEK = (DWORD *)pbTemp;

    E = pdwEK[0];
    F = pdwEK[2];
    G = pdwEK[4];
    H = pdwEK[6];
    KeyExpand0(pbEK, E, F, G, H, C0, C1, C2, C3);

    E = pdwEK[1];
    F = pdwEK[3];
    G = pdwEK[5];
    H = pdwEK[7];
    KeyExpand1(pbEK+16, E, F, G, H, C4, C5, C6, C7);

    pdwEK = pdwExpKey;
    Sum = pdwEK[0] ^ pdwEK[1] ^ pdwEK[2] ^ pdwEK[3];
    pdwEK[4] ^= Sum;
    pdwEK[5] ^= Sum;
    pdwEK[6] ^= Sum;
    pdwEK[7] ^= Sum;

    Sum = pdwEK[4] ^ pdwEK[5] ^ pdwEK[6] ^ pdwEK[7];
    pdwEK[0] ^= Sum;
    pdwEK[1] ^= Sum;
    pdwEK[2] ^= Sum;
    pdwEK[3] ^= Sum;
}

/*********************************************************************/

/*============== Definitions for Round key Generations =============*/

/* masking words for word permutation */
#define    M20    0xcffccffc
#define    M31    0x3ff33ff3
#define    M02    0xfccffccf
#define    M13    0xf33ff33f

/* equivalent to ByteTrans, BitPerm and ByteTrans */
#ifdef BIG_ENDIAN
    #define WordPerm0(A0)                               \
        (      (A0 & M02    ) ^ ROTL(A0 & M31,  8) ^   \
          ROTL(A0 & M20, 16) ^ ROTL(A0 & M13, 24) )
    #define WordPerm1(A1)                               \
        (      (A1 & M13    ) ^ ROTL(A1 & M02,  8) ^   \
          ROTL(A1 & M31, 16) ^ ROTL(A1 & M20, 24) )
    #define WordPerm2(A2)                               \
        (      (A2 & M20    ) ^ ROTL(A2 & M13,  8) ^   \
          ROTL(A2 & M02, 16) ^ ROTL(A2 & M31, 24) )
    #define WordPerm3(A3)                               \
        (      (A3 & M31    ) ^ ROTL(A3 & M20,  8) ^   \
          ROTL(A3 & M13, 16) ^ ROTL(A3 & M02, 24) )
#else
    #define WordPerm0(A0)                               \
        (      (A0 & M20    ) ^ ROTL(A0 & M31,  8) ^   \
          ROTL(A0 & M02, 16) ^ ROTL(A0 & M13, 24) )
    #define WordPerm1(A1)                               \
        (      (A1 & M31    ) ^ ROTL(A1 & M02,  8) ^   \
          ROTL(A1 & M13, 16) ^ ROTL(A1 & M20, 24) )
    #define WordPerm2(A2)                               \
        (      (A2 & M02    ) ^ ROTL(A2 & M13,  8) ^   \
          ROTL(A2 & M20, 16) ^ ROTL(A2 & M31, 24) )
    #define WordPerm3(A3)                               \
        (      (A3 & M13    ) ^ ROTL(A3 & M20,  8) ^   \
          ROTL(A3 & M31, 16) ^ ROTL(A3 & M02, 24) )
#endif


/* appropriate rotation according to endianness */
#ifdef BIG_ENDIAN
    #define ROTATE(X, n)  ROTR(X, n)
#else
    #define ROTATE(X, n)  ROTL(X, n)
#endif


/* Round constants */
#define RC0 0x01010101
#define RC1 0x02020202
#define RC2 0x04040404
#define RC3 0x08080808
#define RC4 0x10101010
#define RC5 0x20202020


/*################# Generate Encryption Round Keys #################*/

void CryptonGenEncRoundKey(pdwEncKey, pdwExpKey)
DWORD *pdwExpKey, *pdwEncKey;
{
    pdwEncKey[ 0] = pdwExpKey[0];
    pdwEncKey[ 8] = ROTATE(pdwEncKey[0], 8);
    pdwEncKey[16] = RC1 ^ pdwEncKey[8];
    pdwEncKey[24] = ROTATE(pdwEncKey[16], 16);
    pdwEncKey[32] = RC3 ^ pdwEncKey[24];
    pdwEncKey[40] = ROTATE(pdwEncKey[32], 24);
    pdwEncKey[48] = RC5 ^ pdwEncKey[40];
    pdwEncKey[48] = WordPerm2(pdwEncKey[48]);

    pdwEncKey[ 1] = pdwExpKey[1];
    pdwEncKey[ 9] = RC0 ^ pdwEncKey[1];
    pdwEncKey[17] = ROTATE(pdwEncKey[9], 24);
    pdwEncKey[25] = RC2 ^ pdwEncKey[17];
    pdwEncKey[33] = ROTATE(pdwEncKey[25], 8);
    pdwEncKey[41] = RC4 ^ pdwEncKey[33];
    pdwEncKey[49] = ROTATE(pdwEncKey[41], 16);
    pdwEncKey[49] = WordPerm3(pdwEncKey[49]);

    pdwEncKey[ 2] = pdwExpKey[2];
    pdwEncKey[10] = ROTATE(pdwEncKey[2], 16);
    pdwEncKey[18] = RC1 ^ pdwEncKey[10];
    pdwEncKey[26] = ROTATE(pdwEncKey[18], 24);
    pdwEncKey[34] = RC3 ^ pdwEncKey[26];
    pdwEncKey[42] = ROTATE(pdwEncKey[34], 8);
    pdwEncKey[50] = RC5 ^ pdwEncKey[42];
    pdwEncKey[50] = WordPerm0(pdwEncKey[50]);

    pdwEncKey[ 3] = pdwExpKey[3];
    pdwEncKey[11] = RC0 ^ pdwEncKey[3];
    pdwEncKey[19] = ROTATE(pdwEncKey[11], 8);
    pdwEncKey[27] = RC2 ^ pdwEncKey[19];
    pdwEncKey[35] = ROTATE(pdwEncKey[27], 16);
    pdwEncKey[43] = RC4 ^ pdwEncKey[35];
    pdwEncKey[51] = ROTATE(pdwEncKey[43], 24);
    pdwEncKey[51] = WordPerm1(pdwEncKey[51]);

    pdwEncKey[ 4] = pdwExpKey[4];
    pdwEncKey[12] = RC0 ^ pdwEncKey[4];
    pdwEncKey[20] = ROTATE(pdwEncKey[12], 8);
    pdwEncKey[28] = RC2 ^ pdwEncKey[20];
    pdwEncKey[36] = ROTATE(pdwEncKey[28], 16);
    pdwEncKey[44] = RC4 ^ pdwEncKey[36];

    pdwEncKey[ 5] = pdwExpKey[5];
    pdwEncKey[13] = ROTATE(pdwEncKey[5], 16);
    pdwEncKey[21] = RC1 ^ pdwEncKey[13];
    pdwEncKey[29] = ROTATE(pdwEncKey[21], 24);
    pdwEncKey[37] = RC3 ^ pdwEncKey[29];
    pdwEncKey[45] = ROTATE(pdwEncKey[37], 8);

    pdwEncKey[ 6] = pdwExpKey[6];
    pdwEncKey[14] = RC0 ^ pdwEncKey[6];
    pdwEncKey[22] = ROTATE(pdwEncKey[14], 16);
    pdwEncKey[30] = RC2 ^ pdwEncKey[22];
    pdwEncKey[38] = ROTATE(pdwEncKey[30], 24);
    pdwEncKey[46] = RC4 ^ pdwEncKey[38];

    pdwEncKey[ 7] = pdwExpKey[7];
    pdwEncKey[15] = ROTATE(pdwEncKey[7], 24);
    pdwEncKey[23] = RC1 ^ pdwEncKey[15];
    pdwEncKey[31] = ROTATE(pdwEncKey[23], 8);
    pdwEncKey[39] = RC3 ^ pdwEncKey[31];
    pdwEncKey[47] = ROTATE(pdwEncKey[39], 16);
}



/*################# Generate Decryption Round Keys #################*/

void CryptonGenDecRoundKey(pdwDecKey, pdwExpKey)
DWORD *pdwExpKey, *pdwDecKey;
{
    pdwDecKey[48] = pdwExpKey[0];
    pdwDecKey[40] = WordPerm2(pdwDecKey[48]);
    pdwDecKey[40] = ROTATE(pdwDecKey[40], 24);
    pdwDecKey[32] = RC1 ^ pdwDecKey[40];
    pdwDecKey[24] = ROTATE(pdwDecKey[32], 16);
    pdwDecKey[16] = RC3^ pdwDecKey[24];
    pdwDecKey[ 8] = ROTATE(pdwDecKey[16], 8);
    pdwDecKey[ 0] = pdwDecKey[ 8] ^ RC5;

    pdwDecKey[49] = pdwExpKey[1];
    pdwDecKey[41] = WordPerm3(pdwDecKey[49]);
    pdwDecKey[41] = RC0 ^ pdwDecKey[41];
    pdwDecKey[33] = ROTATE(pdwDecKey[41], 8);
    pdwDecKey[25] = RC2 ^ pdwDecKey[33];
    pdwDecKey[17] = ROTATE(pdwDecKey[25], 24);
    pdwDecKey[ 9] = RC4 ^ pdwDecKey[17];
    pdwDecKey[ 1] = ROTATE(pdwDecKey[ 9], 16);

    pdwDecKey[50] = pdwExpKey[2];
    pdwDecKey[42] = WordPerm0(pdwDecKey[50]);
    pdwDecKey[42] = ROTATE(pdwDecKey[42], 16);
    pdwDecKey[34] = RC1 ^ pdwDecKey[42];
    pdwDecKey[26] = ROTATE(pdwDecKey[34], 8);
    pdwDecKey[18] = RC3 ^ pdwDecKey[26];
    pdwDecKey[10] = ROTATE(pdwDecKey[18], 24);
    pdwDecKey[ 2] = RC5 ^ pdwDecKey[10];

    pdwDecKey[51] = pdwExpKey[3];
    pdwDecKey[43] = WordPerm1(pdwDecKey[51]);
    pdwDecKey[43] = RC0 ^ pdwDecKey[43];
    pdwDecKey[35] = ROTATE(pdwDecKey[43], 24);
    pdwDecKey[27] = RC2 ^ pdwDecKey[35];
    pdwDecKey[19] = ROTATE(pdwDecKey[27], 16);
    pdwDecKey[11] = RC4 ^ pdwDecKey[19];
    pdwDecKey[ 3] = ROTATE(pdwDecKey[11], 8);

    pdwDecKey[44] = WordPerm0(pdwExpKey[4]);
    pdwDecKey[36] = RC0 ^ pdwDecKey[44];
    pdwDecKey[28] = ROTATE(pdwDecKey[36], 24);
    pdwDecKey[20] = RC2 ^ pdwDecKey[28];
    pdwDecKey[12] = ROTATE(pdwDecKey[20], 16);
    pdwDecKey[ 4] = RC4 ^ pdwDecKey[12];

    pdwDecKey[45] = WordPerm1(pdwExpKey[5]);
    pdwDecKey[37] = ROTATE(pdwDecKey[45], 16);
    pdwDecKey[29] = RC1 ^ pdwDecKey[37];
    pdwDecKey[21] = ROTATE(pdwDecKey[29], 8);
    pdwDecKey[13] = RC3 ^ pdwDecKey[21];
    pdwDecKey[ 5] = ROTATE(pdwDecKey[13], 24);

    pdwDecKey[46] = WordPerm2(pdwExpKey[6]);
    pdwDecKey[38] = RC0 ^ pdwDecKey[46];
    pdwDecKey[30] = ROTATE(pdwDecKey[38], 16);
    pdwDecKey[22] = RC2 ^ pdwDecKey[30];
    pdwDecKey[14] = ROTATE(pdwDecKey[22], 8);
    pdwDecKey[ 6] = RC4 ^ pdwDecKey[14];

    pdwDecKey[47] = WordPerm3(pdwExpKey[7]);
    pdwDecKey[39] = ROTATE(pdwDecKey[47], 8);
    pdwDecKey[31] = RC1 ^ pdwDecKey[39];
    pdwDecKey[23] = ROTATE(pdwDecKey[31], 24);
    pdwDecKey[15] = RC3 ^ pdwDecKey[23];
    pdwDecKey[ 7] = ROTATE(pdwDecKey[15], 16);
}


/************************ Generate CRYPTON S-boxes *********************/
 
void CryptonGenSbox(void)
{
    int i, R, L;
    static BYTE P0[16] = {15, 5,10, 1, 5, 5, 8, 9,10, 2,10, 3, 4, 6,12,15};
    static BYTE P1[16] = {10,15, 4,13, 5, 8,14,12, 3, 9, 6, 2, 7, 1,11, 0};
    static BYTE P2[16] = { 0, 4, 2, 4, 1,15, 2,14, 8, 8,15,13, 1,11, 7,15};

    extern BYTE S0[256], S1[256], S2[256], S3[256];
    extern DWORD SS0[256], SS1[256], SS2[256], SS3[256];


    for(i=0; i<256; ++i) {
        R = i&0xf;
        L = (i>>4) ^ P0[R];
        R ^= P1[L];
        L ^= P2[R];
        R ^= (L<< 4);
        L = ((R<<6) ^ (R>>2)) & 0xff;

         S0[i] = (BYTE)R;
        SS0[i] = PutByte3(R&0x3f) ^ PutByte2(R&0xcf) ^
                 PutByte1(R&0xf3) ^ PutByte0(R&0xfc);
         S1[i] = (BYTE)L;
        SS1[i] = PutByte3(L&0xfc) ^ PutByte2(L&0x3f) ^
                 PutByte1(L&0xcf) ^ PutByte0(L&0xf3);
         S2[R] = (BYTE)i;
        SS2[R] = PutByte3(i&0xf3) ^ PutByte2(i&0xfc) ^
                 PutByte1(i&0x3f) ^ PutByte0(i&0xcf);
         S3[L] = (BYTE)i;
        SS3[L] = PutByte3(i&0xcf) ^ PutByte2(i&0xf3) ^
                 PutByte1(i&0xfc) ^ PutByte0(i&0x3f);
    }
}

/********************************** END ************************************/
