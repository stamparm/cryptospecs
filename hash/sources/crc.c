// ----------------------------------------------------------------------------
// CRC tester v1.3 written on 4th of February 2003 by Sven Reifegerste (zorc/reflex)
// This is the complete compilable C program, consisting only of this .c file.
// No guarantee for any mistakes.
//
// changes to CRC tester v1.2:
//
// - remove unneccessary (!(polynom&1)) test for invalid polynoms
//   (now also XMODEM parameters 0x8408 work in c-code as they should)
//
// changes to CRC tester v1.1:
//
// - include an crc&0crcmask after converting non-direct to direct initial
//   value to avoid overflow
//
// changes to CRC tester v1.0:
//
// - most int's were replaced by unsigned long's to allow longer input strings
//   and avoid overflows and unnecessary type-casting's
// ----------------------------------------------------------------------------

// includes:

#include <string.h>
#include <stdio.h>


// CRC parameters (default values are for CRC-32):

const int order = 32;
const unsigned long polynom = 0x4c11db7;
const int direct = 1;
const unsigned long crcinit = 0xffffffff;
const unsigned long crcxor = 0xffffffff;
const int refin = 1;
const int refout = 1;

// 'order' [1..32] is the CRC polynom order, counted without the leading '1' bit
// 'polynom' is the CRC polynom without leading '1' bit
// 'direct' [0,1] specifies the kind of algorithm: 1=direct, no augmented zero bits
// 'crcinit' is the initial CRC value belonging to that algorithm
// 'crcxor' is the final XOR value
// 'refin' [0,1] specifies if a data byte is reflected before processing (UART) or not
// 'refout' [0,1] specifies if the CRC will be reflected before XOR


// Data character string

const unsigned char string[] = {"123456789"};

// internal global values:

unsigned long crcmask;
unsigned long crchighbit;
unsigned long crcinit_direct;
unsigned long crcinit_nondirect;
unsigned long crctab[256];


// subroutines

unsigned long reflect (unsigned long crc, int bitnum) {

	// reflects the lower 'bitnum' bits of 'crc'

	unsigned long i, j=1, crcout=0;

	for (i=(unsigned long)1<<(bitnum-1); i; i>>=1) {
		if (crc & i) crcout|=j;
		j<<= 1;
	}
	return (crcout);
}



void generate_crc_table() {

	// make CRC lookup table used by table algorithms

	int i, j;
	unsigned long bit, crc;

	for (i=0; i<256; i++) {

		crc=(unsigned long)i;
		if (refin) crc=reflect(crc, 8);
		crc<<= order-8;

		for (j=0; j<8; j++) {

			bit = crc & crchighbit;
			crc<<= 1;
			if (bit) crc^= polynom;
		}			

		if (refin) crc = reflect(crc, order);
		crc&= crcmask;
		crctab[i]= crc;
	}
}


		
unsigned long crctablefast (unsigned char* p, unsigned long len) {

	// fast lookup table algorithm without augmented zero bytes, e.g. used in pkzip.
	// only usable with polynom orders of 8, 16, 24 or 32.

	unsigned long crc = crcinit_direct;

	if (refin) crc = reflect(crc, order);

	if (!refin) while (len--) crc = (crc << 8) ^ crctab[ ((crc >> (order-8)) & 0xff) ^ *p++];
	else while (len--) crc = (crc >> 8) ^ crctab[ (crc & 0xff) ^ *p++];

	if (refout^refin) crc = reflect(crc, order);
	crc^= crcxor;
	crc&= crcmask;

	return(crc);
}



unsigned long crctable (unsigned char* p, unsigned long len) {

	// normal lookup table algorithm with augmented zero bytes.
	// only usable with polynom orders of 8, 16, 24 or 32.

	unsigned long crc = crcinit_nondirect;

	if (refin) crc = reflect(crc, order);

	if (!refin) while (len--) crc = ((crc << 8) | *p++) ^ crctab[ (crc >> (order-8))  & 0xff];
	else while (len--) crc = ((crc >> 8) | (*p++ << (order-8))) ^ crctab[ crc & 0xff];

	if (!refin) while (++len < order/8) crc = (crc << 8) ^ crctab[ (crc >> (order-8))  & 0xff];
	else while (++len < order/8) crc = (crc >> 8) ^ crctab[crc & 0xff];

	if (refout^refin) crc = reflect(crc, order);
	crc^= crcxor;
	crc&= crcmask;

	return(crc);
}



unsigned long crcbitbybit(unsigned char* p, unsigned long len) {

	// bit by bit algorithm with augmented zero bytes.
	// does not use lookup table, suited for polynom orders between 1...32.

	unsigned long i, j, c, bit;
	unsigned long crc = crcinit_nondirect;

	for (i=0; i<len; i++) {

		c = (unsigned long)*p++;
		if (refin) c = reflect(c, 8);

		for (j=0x80; j; j>>=1) {

			bit = crc & crchighbit;
			crc<<= 1;
			if (c & j) crc|= 1;
			if (bit) crc^= polynom;
		}
	}	

	for (i=0; i<order; i++) {

		bit = crc & crchighbit;
		crc<<= 1;
		if (bit) crc^= polynom;
	}

	if (refout) crc=reflect(crc, order);
	crc^= crcxor;
	crc&= crcmask;

	return(crc);
}



unsigned long crcbitbybitfast(unsigned char* p, unsigned long len) {

	// fast bit by bit algorithm without augmented zero bytes.
	// does not use lookup table, suited for polynom orders between 1...32.

	unsigned long i, j, c, bit;
	unsigned long crc = crcinit_direct;

	for (i=0; i<len; i++) {

		c = (unsigned long)*p++;
		if (refin) c = reflect(c, 8);

		for (j=0x80; j; j>>=1) {

			bit = crc & crchighbit;
			crc<<= 1;
			if (c & j) bit^= crchighbit;
			if (bit) crc^= polynom;
		}
	}	

	if (refout) crc=reflect(crc, order);
	crc^= crcxor;
	crc&= crcmask;

	return(crc);
}



int main() {

	// test program for checking four different CRC computing types that are:
	// crcbit(), crcbitfast(), crctable() and crctablefast(), see above.
	// parameters are at the top of this program.
	// Result will be printed on the console.

	int i;
	unsigned long bit, crc;


	// at first, compute constant bit masks for whole CRC and CRC high bit

	crcmask = ((((unsigned long)1<<(order-1))-1)<<1)|1;
	crchighbit = (unsigned long)1<<(order-1);


	// check parameters

	if (order < 1 || order > 32) {
		printf("ERROR, invalid order, it must be between 1..32.\n");
		return(0);
	}

	if (polynom != (polynom & crcmask)) {
		printf("ERROR, invalid polynom.\n");
		return(0);
	}

	if (crcinit != (crcinit & crcmask)) {
		printf("ERROR, invalid crcinit.\n");
		return(0);
	}

	if (crcxor != (crcxor & crcmask)) {
		printf("ERROR, invalid crcxor.\n");
		return(0);
	}

	
	// generate lookup table

	generate_crc_table();


	// compute missing initial CRC value

	if (!direct) {

		crcinit_nondirect = crcinit;
		crc = crcinit;
		for (i=0; i<order; i++) {

			bit = crc & crchighbit;
			crc<<= 1;
			if (bit) crc^= polynom;
		}
		crc&= crcmask;
		crcinit_direct = crc;
	}

	else {

		crcinit_direct = crcinit;
		crc = crcinit;
		for (i=0; i<order; i++) {

			bit = crc & 1;
			if (bit) crc^= polynom;
			crc >>= 1;
			if (bit) crc|= crchighbit;
		}	
		crcinit_nondirect = crc;
	}
	

	// call CRC algorithms using the CRC parameters above and print result to the console

	printf("\n");
	printf("CRC tester v1.1 written on 13/01/2003 by Sven Reifegerste (zorc/reflex)\n");
	printf("-----------------------------------------------------------------------\n");
	printf("\n");
	printf("Parameters:\n");
	printf("\n");
	printf(" polynom             :  0x%x\n", polynom);
	printf(" order               :  %d\n", order);
	printf(" crcinit             :  0x%x direct, 0x%x nondirect\n", crcinit_direct, crcinit_nondirect);
	printf(" crcxor              :  0x%x\n", crcxor);
	printf(" refin               :  %d\n", refin);
	printf(" refout              :  %d\n", refout);
	printf("\n");
	printf(" data string         :  '%s' (%d bytes)\n", string, strlen(string));
	printf("\n");
	printf("Results:\n");
	printf("\n");

	printf(" crc bit by bit      :  0x%x\n", crcbitbybit((unsigned char *)string, strlen(string)));
	printf(" crc bit by bit fast :  0x%x\n", crcbitbybitfast((unsigned char *)string, strlen(string)));
	if (!(order&7)) printf(" crc table           :  0x%x\n", crctable((unsigned char *)string, strlen(string)));
	if (!(order&7)) printf(" crc table fast      :  0x%x\n", crctablefast((unsigned char *)string, strlen(string)));

	return(0);
}
