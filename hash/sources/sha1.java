/******************************************************************************
 *
 * Copyright (c) 1998-2000 by Mindbright Technology AB, Stockholm, Sweden.
 *                 www.mindbright.se, info@mindbright.se
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *****************************************************************************
 * $Author: joey $
 * $Date: 2001/04/06 17:39:30 $
 * $Name:  $
 *****************************************************************************/
package mindbright.security;

public final class SHA1 extends MessageDigest {
    private int[]  hash;
    private int[]  W;
    private long   count;
    private int    rest;
    private byte[] buffer;

    static byte padding[] = {
        (byte) 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    private static int rotateLeft(int x, int n) {
	return (x << n) | (x >>> (32 - n));
    }

    private static int F00_19(int x, int y, int z) {
	return (((y ^ z) & x) ^ z) + 0x5a827999;
    }

    private static int F20_39(int x, int y, int z) {
	return (x ^ y ^ z) + 0x6ed9eba1;
    }

    private static int F40_59(int x, int y, int z) {
	return ((x & y) | ((x | y) & z)) + 0x8f1bbcdc;
    }

    private static int F60_79(int x, int y, int z) {
	return (x ^ y ^ z) + 0xca62c1d6;
    }

    private void transform(byte data[], int offset) {
	int a = hash[0];
	int b = hash[1];
	int c = hash[2];
	int d = hash[3];
	int e = hash[4];
	int t, i;

	for (i = 0; i < 16; i++) {
	    W[i] =
		((((int) (data[offset++] & 0xff)) << 24) |
		 (((int) (data[offset++] & 0xff)) << 16) |
		 (((int) (data[offset++] & 0xff)) <<  8) |
		 (((int) (data[offset++] & 0xff))));
	}

	for(i = 16; i < 80; i++) {
	    t = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16];
	    W[i] = rotateLeft(t, 1);
	}

	for(i = 0; i < 20; i++) {
	    t = rotateLeft(a, 5) + F00_19(b, c, d) + e + W[i];
	    e = d;
	    d = c;
	    c = rotateLeft(b, 30);
	    b = a;
	    a = t;
	}

	for(i = 20; i < 40; i++) {
	    t = rotateLeft(a, 5) + F20_39(b, c, d) + e + W[i];
	    e = d;
	    d = c;
	    c = rotateLeft(b, 30);
	    b = a;
	    a = t;
	}

	for(i = 40; i < 60; i++) {
	    t = rotateLeft(a, 5) + F40_59(b, c, d) + e + W[i];
	    e = d;
	    d = c;
	    c = rotateLeft(b, 30);
	    b = a;
	    a = t;
	}

	for(i = 60; i < 80; i++) {
	    t = rotateLeft(a, 5) + F60_79(b, c, d) + e + W[i];
	    e = d;
	    d = c;
	    c = rotateLeft(b, 30);
	    b = a;
	    a = t;
	}

	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
	hash[4] += e;
    }

    public SHA1() {
	buffer = new byte[64];
	hash   = new int[5];
	W      = new int[80];
	reset();
    }

    private SHA1(SHA1 c) {
	buffer = new byte[64];
	hash   = new int[5];
	W      = new int[80];
	System.arraycopy(c.hash, 0, hash, 0, 5);
	System.arraycopy(c.buffer, 0, buffer, 0, 64);
	count = c.count;
	rest  = c.rest;
    }

    public Object clone() {
	return new SHA1(this);
    }

    public String getName() {
        return "SHA1";
    }

    public void reset() {
	hash[0] = 0x67452301;
	hash[1] = 0xefcdab89;
	hash[2] = 0x98badcfe;
	hash[3] = 0x10325476;
	hash[4] = 0xc3d2e1f0;
	count   = 0;
	rest    = 0;
    }

    public void update(byte[] data, int offset, int length) {
        int left = 64 - rest;

        count += length;

	if(rest > 0 && length >= left) {
	    System.arraycopy(data, offset, buffer, rest, left);
	    transform(buffer, 0);
	    offset += left;
	    length -= left;
	    rest   =  0;
	}

	while(length > 63) {
	    transform(data, offset);
	    offset += 64;
	    length -= 64;
	}

	if(length > 0) {
	    System.arraycopy(data, offset, buffer, rest, length);
	    rest += length;
	}
    }
    
    public byte[] digest() {
	byte[] buf = new byte[20];
	digestInto(buf, 0);
        return buf;
    }

    public int digestInto(byte[] dest, int destOff) {
	int padlen = (rest < 56) ? (56 - rest) : (120 - rest);

	count *= 8;
	byte[] countBytes = {
	    (byte)(count >> 56),
	    (byte)(count >> 58),
	    (byte)(count >> 40),
	    (byte)(count >> 32),
	    (byte)(count >> 24),
	    (byte)(count >> 16),
	    (byte)(count >>  8),
	    (byte)(count)
	};

	update(padding, 0, padlen);
	update(countBytes, 0, 8);

        int i;
        for (i = 0; i < 5; i++) {
            dest[destOff++] = (byte) ((hash[i] >>> 24) & 0xff);
            dest[destOff++] = (byte) ((hash[i] >>> 16) & 0xff);
            dest[destOff++] = (byte) ((hash[i] >>>  8) & 0xff);
            dest[destOff++] = (byte) ((hash[i]) & 0xff);
        }

	reset();
	return 20;
    }

    public int blockSize() {
        return 64;
    }

    public int hashSize() {
        return 20;
    }
}
