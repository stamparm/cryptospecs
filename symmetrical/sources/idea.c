/* idea.c -- idea encryption
 * 1994 by Risto Paasivirta, paasivir@jyu.fi
 */

typedef unsigned long ulong;
typedef unsigned short ushort;
typedef unsigned char uchar;

#define INLINE __inline

/* a * b mod 65537
 */
static INLINE ushort mul(ushort a, ushort b);

static INLINE ushort mul(ushort a, ushort b)
{
  long p;
  ulong q;

  if (a==0)
    return (ushort)(1 - b);
  if (b==0)
    return (ushort)(1 - a);
  q = (ulong)a * (ulong)b;
  if((p = (q & 65535) - (q >> 16)) <= 0)
    p++;
  return (ushort)p;
}

/* a^-1 mod 65537
 */

static INLINE ushort inv(ushort a);

static INLINE ushort inv(ushort ain)
{
  long a = ain, c = 65537, d, e = 0, f = 1, g;

  while ( a > 0 ) {
    d = c % a;
    g = e - c / a * f;
    c = a; a = d; e = f; f = g;
  }
  if (e < 0)
    e++;
  return (ushort)e;
}

/* IDEA core function
 */

void
Idea(ushort *in, ushort *out, ushort *ks)
{
  ushort x0, x1, x2, x3, a, b, i;

  x0 = in[0];
  x1 = in[1];
  x2 = in[2];
  x3 = in[3];
  for (i = 0; i < 8; i++) {
    x0 = mul(*ks++, x0);
    x1 += *ks++;
    x2 += *ks++; 
    x3 = mul(*ks++, x3);
    b = mul(*ks++, x0 ^ x2);
    a = mul(*ks++, b + (x1 ^ x3));
    b += a;
    x0 = a ^ x0;
    x3 = b ^ x3;
    b ^= x1;
    x1 = a ^ x2;
    x2 = b;
  }
  out[0] = mul(*ks++, x0);
  out[1] = *ks++ + x2;
  out[2] = *ks++ + x1;
  out[3] = mul(*ks, x3);
}

/* Expand 128-bit user key to 832-bit encrypt key
 */

void
ExpandUserKey(ushort *key, ushort *ks)
{
  ushort i;

  for (i = 0; i < 8; i++)
    ks[i] = key[i];
  for (;i < 52; i++) {
    if ((i & 7) == 6) {
      ks[i] = (ks[i - 7] << 9) ^ (ks[i - 14] >> 7);
    } else if ((i & 7) == 7) {
      ks[i] = (ks[i - 15] << 9) ^ (ks[i - 14] >> 7);
    } else {
      ks[i] = (ks[i - 7] << 9) ^ (ks[i - 6] >> 7);
    }
  }
}

/* Invert encrypt key to decrypt key.
 */

void
InvertIdeaKey(ushort *ks, ushort *ik)
{
  ushort kb[52], i, j;

  for (i = 0, j = 48; i < 52; i += 6, j -= 6) {
    kb[i + 0] = inv(ks[j + 0]);
    if ((i == 0) || (i == 48)) {
      kb[i + 1] = -ks[j + 1];
      kb[i + 2] = -ks[j + 2];
    } else {
      kb[i + 1] = -ks[j + 2];
      kb[i + 2] = -ks[j + 1];
    }
    kb[i + 3] = inv(ks[j + 3]);
    if (i < 48) {
      kb[i + 4] = ks[j - 2];
      kb[i + 5] = ks[j - 1];
    }
  }
  for (i = 0; i < 52; i++)
    ik[i] = kb[i];
}

