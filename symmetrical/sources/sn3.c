/* SN3 implementation. Public Domain. No warranty of any kind. */ 
/* Author: Simeon Maltchev, smaltc...@yahoo.com */ 


#include <stdio.h> 
#include <string.h> 


typedef unsigned long int u32; 


#define TABLE_SIZE 64 
#define SBOX_SIZE (3 * TABLE_SIZE) 
#define INDEX_MASK (TABLE_SIZE - 1) 


#define rotl(a, b) (((a) << ((b) & 31)) | ((a) >> (32 - ((b) & 31)))) 


u32 keystream[SBOX_SIZE]; 
u32 seed[SBOX_SIZE]; 


char *simple_key = "abcdefgh"; 


void sn3(); 
void init_seed(char *key, u32 key_len); 
void print_keystream(); 


int main() 
{ 
        init_seed(simple_key, strlen(simple_key)); 


        sn3(); 
        print_keystream(); 


        sn3(); 
        print_keystream(); 


        return 0; 


} 


/* Call this function to generate 192 random 32-bit values. */ 
void sn3() 
{ 
        u32 *v1, *v2, *v3, *temp; 
        u32 t1, t2, t3, i, m, k, n, n1, n2; 
        static u32 j = 0; 


        v1 = seed; 
        v2 = v1 + TABLE_SIZE; 
        v3 = v2 + TABLE_SIZE; 
        i = n = 0; 
        for (n1 = 0; n1 < 3; n1++) 
        { 
                for (n2 = 0; n2 < TABLE_SIZE; n2++) 
                { 
                        t1 = v1[i]; 
                        t2 = v2[j]; 
                        m  = t1 & INDEX_MASK; 
                        t3 = v3[m]; 


                        k  = t1 ^ t2 ^ t3; 


                        v1[i] = rotl(t1, 1)  ^ t2; 
                        v2[j] = rotl(t2, 5)  ^ t3 ^ 0x8c591ca1; 
                        v3[m] = rotl(t3, 17) ^ t1 ^ 0xab8ec254; 


                        i++; 
                        i &= INDEX_MASK; 
                        j = (t1 >> 8) & INDEX_MASK; 


                        keystream[n++] = k; 
                } 


                temp = v1; 
                v1   = v2; 
                v2   = v3; 
                v3   = temp; 
        } 


} 


void init_seed(char *key, u32 key_len) 
{ 
        u32 i, j; 
        char *char_seed = (char *) seed; 


        for (i = j = 0; i < SBOX_SIZE*sizeof(u32); i++, j++) 
        { 
                if (j == key_len) 
                        j = 0; 
                char_seed[i] = key[j]; 
        } 


        sn3(); 
        for (i = 0; i < SBOX_SIZE; i++) 
                seed[i] = rotl(seed[i], 19) ^ keystream[i]; 


} 


void print_keystream() 
{ 
        u32 i; 


        for (i = 1; i <= SBOX_SIZE; i++) { 
                printf("%08x\t", keystream[i - 1]); 
                if (i % 4 == 0) 
                        printf("\n"); 
        } 
        printf("\n\n"); 


}