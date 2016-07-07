/**********************************************************
   TEA - Tiny Encryption Algorithm
   Feistel cipher by David Wheeler & Roger M. Needham
   (extended version)
 **********************************************************/

#define ROUNDS 32
#define DELTA 0x9e3779b9 /* sqr(5)-1 * 2^31 */

#include "ctypes.h"

/**********************************************************
   Input values: 	k[4]	128-bit key
			v[2]    64-bit plaintext block
   Output values:	v[2]    64-bit ciphertext block 
 **********************************************************/

void tean(word32 *k, word32 *v, long N) {
  word32 y=v[0], z=v[1];
  word32 limit,sum=0;
  if(N>0) { /* ENCRYPT */
    limit=DELTA*N;
    while(sum!=limit) {
      y+=((z<<4)^(z>>5)) + (z^sum) + k[sum&3];
      sum+=DELTA;
      z+=((y<<4)^(y>>5)) + (y^sum) + k[(sum>>11)&3];
    }
  } else { /* DECRYPT */
    sum=DELTA*(-N);
    while(sum) {
      z-=((y<<4)^(y>>5)) + (y^sum) + k[(sum>>11)&3];
      sum-=DELTA;
      y-=((z<<4)^(z>>5)) + (z^sum) + k[sum&3];
    }
  }
  v[0]=y; v[1]=z;
}

void cl_enc_block(word32 *k, word32 *v) {
 tean(k,v,ROUNDS);
}

void cl_dec_block(word32 *k, word32 *v) {
 tean(k,v,-ROUNDS);
}
