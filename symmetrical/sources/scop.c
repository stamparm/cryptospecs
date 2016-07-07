/* Demo program of SCOP */
 
/* The original implimentation of data encryption part of SCOP (
   functions encrypt/decrypt) is in Intel Assembler. Following are
   given a partially optimized C versions of these functions.
 
   SCOP is tested with MSVC 4.1 and 5.0, and with gcc 2.7.x.
   Please be careful with Borland's 32-bit C compiler. Read the
   comment in the encrypt/decrypt functions. */
 
#include <stdio.h>
#include <assert.h>
 
#define MESSAGE_WORDS 1024
 
typedef struct {
  unsigned long v[384];
  unsigned char i;
  unsigned char j;
  unsigned char t3;
} st_key;
 
typedef struct {
  unsigned char coef[8][4];
  unsigned long x[4];
} st_gp8;
 
st_key kt;
st_gp8 int_state;
unsigned long buf[MESSAGE_WORDS];
 
static void gp8 (unsigned long *out);
 
static void
expand_key (unsigned char *in, unsigned in_size)
{
  unsigned i;
  unsigned char *p;
  unsigned char counter;
 
  assert (in_size >= 2 && in_size <= 48);
 
  p = (unsigned char *) &int_state;
 
  for (i = 0; i < in_size; i++)
    p[i] = in[i];
 
  for (i = in_size; i < 48; i++)
    p[i] =(unsigned char) (p[i - in_size] + p[i - in_size + 1]);
 
  counter = 1;
  for (i = 0; i < 32; i++)
    {
      if (p[i] == 0)
        p[i] = counter++;
    }
}
 
void
init_key (unsigned char *in, unsigned in_size)
{
  unsigned long odd;
  unsigned long t[4];
  int i, j;
 
  expand_key (in, in_size);
 
  for (i = 0; i < 8; i++)
    gp8 (t);
 
  for (i = 0; i < 12; i++)
    {
      for (j = 0; j < 8; j++)
        gp8 (kt.v + i * 32 + j * 4);
 
      gp8 (t);
    }
 
  gp8 (t);
  kt.i  = (unsigned char) (t[3] >> 24);
  kt.j  = (unsigned char) (t[3] >> 16);
  kt.t3 = (unsigned char) (t[3] >> 8);
 
  odd = t[3] & 0x7f;
  kt.v[odd] |= 1;
}
 
/* partially optimized version */
static void
gp8 (unsigned long *out)
{
  unsigned long y1, y2, x_1, x_2, x_3, x_4;
  unsigned long newx[4];
  int i, i2;
 
  for (i = 0; i < 8; i += 2)
    {
      i2 = i >> 1;
 
      x_1 = int_state.x[i2] >> 16;
      x_2 = x_1 * x_1;
      x_3 = x_2 * x_1;
      x_4 = x_3 * x_1;
 
      y1 = int_state.coef[i][0] * x_4 +
           int_state.coef[i][1] * x_3 +
           int_state.coef[i][2] * x_2 +
           int_state.coef[i][3] * x_1 + 1;
 
      x_1 = int_state.x[i2] & 0xffffL;
      x_2 = x_1 * x_1;
      x_3 = x_2 * x_1;
      x_4 = x_3 * x_1;
 
      y2 = int_state.coef[i + 1][0] * x_4 +
           int_state.coef[i + 1][1] * x_3 +
           int_state.coef[i + 1][2] * x_2 +
           int_state.coef[i + 1][3] * x_1 + 1;
 
      out[i2]  = (y1 << 16) | (y2 & 0xffffL);
      newx[i2] = (y1 & 0xffff0000L) | (y2 >> 16);
    }
 
  int_state.x[0] = (newx[0] >> 16) | (newx[3] << 16);
  int_state.x[1] = (newx[0] << 16) | (newx[1] >> 16);
  int_state.x[2] = (newx[1] << 16) | (newx[2] >> 16);
  int_state.x[3] = (newx[2] << 16) | (newx[3] >> 16);
}
 
/* partially optimized version */
void
encrypt (unsigned long *buf, int buflen, st_key *skey)
{
  unsigned char i, j;
  unsigned long t1, t2, t3;
  unsigned long k, t;
  unsigned long *word, *v;
 
  i  = skey->i;
  j  = skey->j;
  t3 = skey->t3;
  v  = skey->v;
  word = buf;
  while (word < buf + buflen)
    {
      t1 = v[128 + j];
      j += t3;
      t  = v[i];
      t2 = v[128 + j];
 
      /* If you want to compile with Borland's 32-bit C compiler using
         optimizations, change the line below to:
         i = (i + 1) & 255; */
      i++;
 
      t3 = t2 + t;
      v[128 + j] = t3;
      j += t2;
      k  = t1 + t2;
 
      *word++ += k;
    }
}
 
/* partially optimized version */
void
decrypt (unsigned long *buf, int buflen, st_key *skey)
{
  unsigned char i, j;
  unsigned long t1, t2, t3;
  unsigned long k, t;
  unsigned long *word, *v;
 
  i  = skey->i;
  j  = skey->j;
  t3 = skey->t3;
  v  = skey->v;
  word = buf;
  while (word < buf + buflen)
    {
      t1 = v[128 + j];
      j += t3;
      t  = v[i];
      t2 = v[128 + j];
 
      /* If you want to compile with Borland's 32-bit C compiler using
         optimizations, change the line below to:
         i = (i + 1) & 255; */
      i++;
 
      t3 = t2 + t;
      v[128 + j] = t3;
      j += t2;
      k  = t1 + t2;
 
      *word++ -= k;
    }
}
 
void
main (void)
{
  unsigned char key[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
14, 15};
 
  unsigned long t;
  int i, flag;
 
  printf ("1\n");
  init_key (key, sizeof (key));
 
  printf ("2\n");
  for (i = 0; i < MESSAGE_WORDS; i++)
    buf[i] = 0L;
 
  printf ("3\n");
  encrypt (buf, MESSAGE_WORDS, &kt);
 
  printf ("4\n");
  t = 0L;
  for(i = 0; i < MESSAGE_WORDS; i++)
    t ^= buf[i];
 
  printf ("XOR of buf is %08lx.\n",t);
 
  init_key (key, sizeof (key));
  decrypt (buf, MESSAGE_WORDS, &kt);
 
  flag = 0;
  for (i = 0; i < MESSAGE_WORDS; i++)
    {
      if (buf[i] != 0L)
        flag = 1;
    }
 
  if (flag)
    printf ("Decrypt failed.\n");
  else
    printf ("Decrypt succeeded.\n");
}
