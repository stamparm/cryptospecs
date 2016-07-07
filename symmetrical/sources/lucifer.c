/***************************** lucifer *************************
 * LUCIFER: encrypt/decrypt bytes using IBM's LUCIFER algorithm.
 * Programmed by R.W.Outerbridge
 *
 * Usage: lucifer (+|-)([ecb]|<cbc|cks>) key1 <ivec>
 *                EN/DE      MODES         KEYS
 *
 *      + :     ENcrypt (default if MODE specified)
 *      - :     DEcrypt (presumes encrypted input)
 *
 *      Modes of Operation (choose ONE):
 *
 *      ecb : (default) Electronic Code Book.  Only uses one key.
 *              If simply "+" or "-" is specified, ecb is used.
 *      cbc : Cipher Block Chaining.  Uses two keys.
 *      cks : ChecKSum.  Generates a 128-bit checksum using two keys.
 *
 *      Both keys may be up to 16 characters long.  NON-ASCII MACHINES
 *      MAY GET DIFFERENT RESULTS.  Any character may be used in keys,
 *      but the one letter key "@", when used as "key1", will cause
 *      lucifer to use a preset default key for "key1".  This is used
 *      for verification and testing.  Failing to specify "ivec", if
 *      required, will result in "key1" being used for both keys.  It
 *      is an error to omit "key1".  There is no provision for specifying
 *      arbitrary, absolute, bit-valued keys.
 *
 *      As painful as they are to use, long keys are MUCH safer.
 *
 *                                      ~~ Graven Cyphers, 8404.16
 *                                         University of Toronto
 */

#include <stdio.h>
#define toascii(a)      ((a)&0177)
#define EN      0
#define DE      1
#define CKS     2
#define MODS    3
typedef char    BYTE;   /* BYTE = (VAX) ? int : char;   */
/* typedef int     void;   /* void = ("void") ? N/A : int; YYYY */

/* cryptographic declarations   */
void copy16(), xor16(), getkey(), loadkey(), lucifer();
BYTE Block[16], Link[16], Temp[16], IV[16];
BYTE DFLTKY[16] = { 1,35,69,103,137,171,205,239,254,220,186,152,118,84,50,16 };
        /* DO NOT ALTER! => 0x0123456789abcdeffedcba9876543210 <=       */

/* I/O declarations     */
void ruderr(), put16(), vraiput(), initio();
int IOedf, End, Once;
BYTE Last[16];

int Ecb(), Cbc(), Cks();
struct modes {
        char *name;
        int (*func)();
        };
struct modes ModsOp[MODS] = {   /* CAPS for CP/M - sorry!       */
        { "ECB", Ecb },
        { "CBC", Cbc },
        { "CKS", Cks }  };

char *prog_name;

int
main(argc, argv)
int argc;
char **argv;
        {
        int (*xeqtr)();
        int step, ende, edio, ok, i;
        BYTE kv[16];

	prog_name = *argv;
        argv++; argc--;
        if(argc > 3 || argc < 2) ruderr();

        for(step=0; argc > 0; step++) {
                switch(step) {
                case 0: /* set en/de and/or default mode        */
                        if(*argv[0] == '+' || *argv[0] == '-') {
                                ende = (*argv[0] == '+') ? EN : DE;
                                *argv[0]++ = NULL;
                                if(*argv[0] == NULL) {
                                        xeqtr = Ecb;    /* default mode */
                                        edio = ende;
                                        argv++; argc--;
                                        break;
                                        }
                                }
                        else ende = EN;

                        for(i=ok=0; i < MODS && !ok; i++) {
                                if(strcmp(argv[0], ModsOp[i].name) == 0) {
                                        xeqtr = ModsOp[i].func;
                                        ok = 1;
                                        }
                                }
                        if(!ok) {
                                fprintf(stderr,"%s:  unknown mode %s\n",prog_name,argv[0]);
                                ruderr();
                                }
                        while(*argv[0]) *argv[0]++ = NULL;
                        argv++; argc--;

                        /* set appropriate IO modes     */
                        if(xeqtr == Cks) edio = CKS;
                        else edio = ende;

                /* falling through....  */
                case 1: /* get the key and IV, if needed and present    */
                        if(strcmp(argv[0], "@") == 0) copy16(DFLTKY, kv);
                        else getkey(argv[0], kv);
                        argv++; argc--;
                        
                        /* if nothing left, but an IV needed, use the key       */
                        if(argc == 0) {
                                if(xeqtr != Ecb) copy16(kv, IV);
                                break;
                                }
                        else if(xeqtr == Ecb) {
                                fprintf(stderr,"%s:  ivec ignored\n",prog_name);
                                while(*argv[0]) *argv[0]++ = NULL;
                                argv++; argc--;
                                break;
                                }

                        else getkey(argv[0], IV);
                        argv++; argc--;
                        break;

                default:
                        fprintf(stderr,"%s:  warning, programming error!\n",prog_name);
                        exit(1);
                        break;
                        }       /* switch       */
                }       /* argument parsing     */

        initio(edio);
        loadkey(kv, ende);
        (*xeqtr)(ende);         /* ta-da!  Take it away xeqtr!  */
        exit(0);
        }       /* end of main  */

void ruderr() {
        fprintf(stderr,"Usage:\n\t%s (+|-)([ecb]|<cbc|cks>) key1 <ivec>\n",prog_name);
	fprintf(stderr,"\n\t+   - Encode\n\t-   - Decode\n\tecb - Electronic Code Book (default)\n");
	fprintf(stderr,"\tcbc - Cipher Block Chaining (ivec required)\n");
	fprintf(stderr,"\tcks - Generate 128 bit checksum\n");
        exit(1);
        }

Cbc(e_d)        /* Cipher Block Chaining                */
int e_d;        /* Ciphertext errors are self-healing.  */
        {
        copy16(IV, Link);
        while(get16(Block) != EOF) {
                if(e_d == DE) copy16(Block, Temp);
                else xor16(Block, Link);
                lucifer(Block);
                if(e_d == DE) {
                        xor16(Block, Link);
                        copy16(Temp, Link);
                        }
                else copy16(Block, Link);
                put16(Block);
                }
        return;
        }

Cks(dummy)      /* CBC authentication checksum generator        */
int dummy;      /* The banks use this for verifications.        */
        {
        int i, j, k;
        long count = 0;
        copy16(IV, Link);
        while(get16(Block) != EOF) {
                xor16(Block, Link);
                lucifer(Block);
                copy16(Block, Link);
                count += 16L;
                }
        fprintf(stdout, ": %0ld bytes\t: ", count);
        for(i=j=0; i < 4; i++) {
                for(k=0; k < 4; k++, j++) fprintf(stdout, "%02x", Link[j]&0377);
                putc(' ', stdout);
                }
        fprintf(stdout, ":\n");
        return;
        }

Ecb(dummy)      /* Electronic Code Book : simple substitution   */
int dummy;      /* Yawn.  For static data and random access.    */
        {
        while(get16(Block) != EOF) {
                lucifer(Block);
                put16(Block);
                }
        return;
        }

void copy16(from, to)
register BYTE *from, *to;
        {
        register BYTE *ep;
        ep = &to[16];
        while(to < ep) *to++ = *from++;
        return;
        }

void xor16(to, with)
register BYTE *to, *with;
        {
        register BYTE *ep;
        ep = &to[16];
        while(to < ep) *to++ ^= *with++;
        return;
        }

void put16(block)
register BYTE *block;
        {
        if(IOedf == DE) copy16(block, Last);
        else vraiput(block, &block[16]);
        return;
        }

get16(input)
register char *input;
        {
        register int i, j;
        if(End == 1) return(EOF);       /* no more input        */

        for(i=0; i < 16 && ((j = getc(stdin)) != EOF); i++) *input++ = j;

        if(IOedf == DE) {       /* DECRYPTION   */
                if(i == 16 && (Once > 0)) vraiput(Last, &Last[16]);
                else if(j == EOF) {
                        End = 1;
                        if(Once > 0) {
                                if(i != 0) i = 0;       /* no NULLs     */
                                else {  
                                        i = Last[15]&037;
                                        if(i > 16) i = 0;       /* huh? */
                                        }
                                vraiput(Last, &Last[16-i]);
                                }
                        return(EOF);
                        }
                }
        else if(j == EOF) {     /* ENCRYPTION   */
                End = 1;
                if(i == 0 && (IOedf == EN || (Once > 0))) {
                        if(IOedf == EN && (Once > 0)) putc('0', stdout);
                        return(EOF);
                        }
                for(j=i; j < 15; j++) *input++ = NULL;
                *input = 16-i;
                }
        Once = 1;
        return(0);
        }

void vraiput(cp, ep)
register char *cp, *ep;
        {
        while(cp < ep) putc(*cp++, stdout);
        return;
        }

void initio(edf)
int edf;
        {
        IOedf = edf;
        End = Once = 0;
        return;
        }

/* LUCIFER is a cryptographic algorithm developed by IBM in the early
 *      seventies.  It was a predecessor of the DES, and is much simpler
 *      than that algorithm.  In particular, it has only two substitution
 *      boxes and just one permutation box.  The permutation box is only
 *      eight bits wide.  It does, however, use a 128 bit key and operates
 *      on sixteen byte data blocks...
 *
 *      This implementation of LUCIFER was crafted by Graven Cyphers at the
 *      University of Toronto, Canada, with programming assistance from
 *      Richard Outerbridge.  It is based on the FORTRAN routines which
 *      concluded Arthur Sorkin's article "LUCIFER: A Cryptographic Algorithm",
 *      CRYPTOLOGIA, Volume 8, Number 1, January 1984, pp22-42.  The interested
 *      reader should refer to that article rather than this program for more
 *      details on LUCIFER.
 *
 *      These routines bear little resemblance to the actual LUCIFER algorithm,
 *      which has been severely twisted in the interests of speed.  They do
 *      perform the same transformations, and are believed to be UNIX portable.
 *      The package was developed for use on UNIX-like systems lacking crypto
 *      facilities.  They are not very fast, but the cipher is very strong.
 *      The routines in this file are suitable for use as a subroutine library
 *      after the fashion of crypt(3).  When linked together with applications
 *      routines they can also provide a high-level cryptographic system.
 */

static BYTE Dps[64] = {         /* Diffusion Pattern schedule   */
        4,16,32,2,1,8,64,128,   128,4,16,32,2,1,8,64,
        64,128,4,16,32,2,1,8,   8,64,128,4,16,32,2,1,
        1,8,64,128,4,16,32,2,   2,1,8,64,128,4,16,32,
        32,2,1,8,64,128,4,16,   16,32,2,1,8,64,128,4    };

/* Precomputed S&P Boxes, Two Varieties */
static char TCB0[256] = {       /* NB: char to save space.      */
         87, 21,117, 54, 23, 55, 20, 84,116,118, 22, 53, 85,119, 52, 86,
        223,157,253,190,159,191,156,220,252,254,158,189,221,255,188,222,
        207,141,237,174,143,175,140,204,236,238,142,173,205,239,172,206,
        211,145,241,178,147,179,144,208,240,242,146,177,209,243,176,210,
        215,149,245,182,151,183,148,212,244,246,150,181,213,247,180,214,
         95, 29,125, 62, 31, 63, 28, 92,124,126, 30, 61, 93,127, 60, 94,
        219,153,249,186,155,187,152,216,248,250,154,185,217,251,184,218,
         67,  1, 97, 34,  3, 35,  0, 64, 96, 98,  2, 33, 65, 99, 32, 66,
        195,129,225,162,131,163,128,192,224,226,130,161,193,227,160,194,
        199,133,229,166,135,167,132,196,228,230,134,165,197,231,164,198,
        203,137,233,170,139,171,136,200,232,234,138,169,201,235,168,202,
         75,  9,105, 42, 11, 43,  8, 72,104,106, 10, 41, 73,107, 40, 74,
         91, 25,121, 58, 27, 59, 24, 88,120,122, 26, 57, 89,123, 56, 90,
         71,  5,101, 38,  7, 39,  4, 68,100,102,  6, 37, 69,103, 36, 70,
         79, 13,109, 46, 15, 47, 12, 76,108,110, 14, 45, 77,111, 44, 78,
         83, 17,113, 50, 19, 51, 16, 80,112,114, 18, 49, 81,115, 48, 82 };

static char TCB1[256] = {
         87,223,207,211,215, 95,219, 67,195,199,203, 75, 91, 71, 79, 83,
         21,157,141,145,149, 29,153,  1,129,133,137,  9, 25,  5, 13, 17,
        117,253,237,241,245,125,249, 97,225,229,233,105,121,101,109,113,
         54,190,174,178,182, 62,186, 34,162,166,170, 42, 58, 38, 46, 50,
         23,159,143,147,151, 31,155,  3,131,135,139, 11, 27,  7, 15, 19,
         55,191,175,179,183, 63,187, 35,163,167,171, 43, 59, 39, 47, 51,
         20,156,140,144,148, 28,152,  0,128,132,136,  8, 24,  4, 12, 16,
         84,220,204,208,212, 92,216, 64,192,196,200, 72, 88, 68, 76, 80,
        116,252,236,240,244,124,248, 96,224,228,232,104,120,100,108,112,
        118,254,238,242,246,126,250, 98,226,230,234,106,122,102,110,114,
         22,158,142,146,150, 30,154,  2,130,134,138, 10, 26,  6, 14, 18,
         53,189,173,177,181, 61,185, 33,161,165,169, 41, 57, 37, 45, 49,
         85,221,205,209,213, 93,217, 65,193,197,201, 73, 89, 69, 77, 81,
        119,255,239,243,247,127,251, 99,227,231,235,107,123,103,111,115,
         52,188,172,176,180, 60,184, 32,160,164,168, 40, 56, 36, 44, 48,
         86,222,206,210,214, 94,218, 66,194,198,202, 74, 90, 70, 78, 82 };

static BYTE Key[16],Pkey[128];
static int P[8] = { 3,5,0,4,2,1,7,6 };
static int Smask[16] = { 128,64,32,16,8,4,2,1 };

void lucifer(bytes)
BYTE *bytes;    /* points to a 16-byte array    */
        {
        register BYTE *cp, *sp, *dp;
        register int *sbs, tcb, val, j, i;
        BYTE *h0, *h1, *kc, *ks;

        h0 = &bytes[0];         /* the "lower" half     */
        h1 = &bytes[8];         /* the "upper" half     */
        kc = Pkey;
        ks = Key;

        for(i=0; i<16; i++) {
                tcb = *ks++;
                sbs = Smask;
                dp = Dps;

                for(j=0; j<8; j++) {
                        /* nibbles are selected by the bits of ks       */
                        if(tcb&*sbs++) val = TCB1[h1[j]&0377];
                        else val = TCB0[h1[j]&0377];
                        val ^= *kc++;

                        /* fiddle bits in the "lower" half      */
                        for(cp=h0, sp = &h0[8]; cp<sp; cp++)
                                *cp ^= (val&*dp++);
                        }

                /* swap (virtual) halves        */
                cp = h0;
                h0 = h1;
                h1 = cp;
                }

        /* REALLY swap halves   */
        dp = &bytes[0];
        cp = &bytes[8];
        for(sp=cp; dp<sp; dp++, cp++) {
                val = *dp;
                *dp = *cp;
                *cp = val;
                }
        return;
        } 

void loadkey(keystr, edf)       /* sets master key      */
BYTE *keystr;
register int edf;
        {
        register BYTE *ep, *cp, *pp;
        register int kc, i, j;
        BYTE kk[16], pk[16];
        cp = kk;
        pp = pk;
        ep = &kk[16];
        while(cp < ep) {
                *cp++ = *keystr;
                for(*pp=i=0; i<8; i++)
                        if(*keystr&Smask[i]) *pp |= Smask[P[i]];
                keystr++;
                pp++;
                }
        cp = Key;
        pp = Pkey;
        kc = (edf == DE) ? 8 : 0;
        for(i=0; i<16; i++) {
                if(edf == DE) kc = (++kc)&017;
                *cp++ = kk[kc];
                for(j=0; j<8; j++) {
                        *pp++ = pk[kc];
                        if(j<7 || (edf == DE)) kc = (++kc)&017;
                        }
                }
        return;
        }

/* getkey: using up to 16 bytes of aptr, makeup a 16 byte key in savp.
        aptr must be NULL terminated, savp 16 bytes long.  The key
        returned in savp is aptr encrypted with itself ONCE.    */ 
void getkey(aptr, savp)
register char *aptr;
register BYTE *savp;
        {
        register BYTE *store, *cp;
        register int i;
        store = savp;

        /* copy aptr into savp; NULL aptr       */
        for(i=0; i<16 && (*aptr != NULL); i++) {
                *savp++ = toascii(*aptr);
                *aptr++ = NULL;
                }
        while(*aptr) *aptr++ = NULL;
        if(i == 0) savp++;      /* aptr could have been NULL    */

        /* expand savp out to 16 bytes of "something" and encrypt it    */
        for(cp=store, savp--; i<16;) store[i++] = (*cp++ + *savp++)&0377;
        loadkey(store);
        lucifer(store);
        return;
        }

