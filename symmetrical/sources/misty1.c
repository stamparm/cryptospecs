/*
 * Presented by H2NP.
 * 
 *   Name: MISTY1 module -- C source code version.
 *   See Also: Internet Draft -- 
 *             A Description of the MISTY1 Encryption Algorithm
 *   Document File: draft-ohta-misty1desc-00.txt
 *
 *   Author: Hironobu SUZUKI
 *   EMAIL: hironobu@h2np.suginami.tokyo.jp
 *   URL: http://www.pp.iij4u.or.jp/~h2np
 *   Copyright Notice: Copyright (C) 1998, Hironobu SUZUKI.
 *   Copyright Condition: GNU GENERAL PUBLIC LICENSE Version 2
 *   Date: 11 January 1998
 *
 */









static void bcopy_u4_byte(u4 k, byte * b) { 
  b[0]=(k>>24)&0xFF;
  b[1]=(k>>16)&0xFF;
  b[2]=(k>>8)&0xFF;
  b[3]= k &0xFF;
}
void misty1_keyinit(u4  *ek, u4  *k)
{
  int i;
  byte key[16];

  bcopy_u4_byte(k[0],(byte *)(&key[0]));
  bcopy_u4_byte(k[1],(byte *)(&key[4]));
  bcopy_u4_byte(k[2],(byte *)(&key[8]));
  bcopy_u4_byte(k[3],(byte *)(&key[12]));
  
  bzero(ek,MISTY1_KEYSIZE*sizeof(u4));
  for(i=0; i < 8 ; i++) {
    ek[i] = (key[i*2]*256) + (key[(i*2) +1]);
  }

  for (i=0 ; i < 8 ; i++) {
    ek[i+8] = fi(ek[i],ek[(i+1)%8]);
    ek[i+16] = ek[i+8] & 0x1ff;
    ek[i+24] = ek[i+8] >> 9;
  }
}

misty1_key_destroy(u4  *ek)
{
  bzero(ek,MISTY1_KEYSIZE*sizeof(u4));
}

#ifdef TESTMAIN
main()
{
/*
   Key:        00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
   Plaintext:  01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
   Ciphertext: 8b 1d a5 f5 6a b3 d0 7c 04 b6 82 40 b1 3b e9 5d
*/


   u4  Key[]= {0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff};
   u4  Plaintext[]= {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};
   u4  Ciphertext[]= { 0x8b1da5f5, 0x6ab3d07c, 0x04b68240, 0xb13be95d};
   u4  ek_e[MISTY1_KEYSIZE],  ek_d[MISTY1_KEYSIZE];
   u4  c[4];

   misty1_keyinit(ek_e,Key);
   misty1_encrypt_block(ek_e,&Plaintext[0],&c[0]);
   misty1_encrypt_block(ek_e,&Plaintext[2],&c[2]);

   if (!memcmp(c,Ciphertext,4 * sizeof(u4))) {
     printf("Encryption OK\n");
   }
   else {
     printf("Encryption failed[0x%08lx 0x%08lx 0x%08lx 0x%08lx]\n",
	    c[0],c[1],c[2],c[3]);
     exit(1);
   }

   misty1_keyinit(ek_d,Key);

   if (memcmp(ek_e,ek_d,MISTY1_KEYSIZE*sizeof(u4))) {
     printf("Internal Error keysch is wrong\n");     
     exit(1);
   }
   
   misty1_decrypt_block(ek_d,&Ciphertext[0],&c[0]);
   misty1_decrypt_block(ek_d,&Ciphertext[2],&c[2]);


   if (!memcmp(c,Plaintext,4 * sizeof(u4))) {
     printf("Decryption OK\n");
   }
   else {
     
     printf("Decryption failed[0x%08lx 0x%08lx 0x%08lx 0x%08lx]\n",
	    c[0],c[1],c[2],c[3]);
     exit(1);
   }

   misty1_key_destroy(ek_e);
   misty1_key_destroy(ek_d);
   bzero(Key,4 * sizeof(u4));

   

}
#endif TESTMAIN
