/*************************************************
* ISAAC Source File                              *
* (C) 1999-2005 The Botan Project                *
*************************************************/

#include <botan/isaac.h>

namespace Botan {

/*************************************************
* Combine Cipher Stream with Message             *
*************************************************/
void ISAAC::cipher(const byte in[], byte out[], u32bit length)
   {
   while(length >= buffer.size() - position)
      {
      xor_buf(out, in, buffer + position, buffer.size() - position);
      length -= (buffer.size() - position);
      in += (buffer.size() - position);
      out += (buffer.size() - position);
      generate();
      }
   xor_buf(out, in, buffer + position, length);
   position += length;
   }

/*************************************************
* Generate ISAAC Cipher Stream                   *
*************************************************/
void ISAAC::generate()
   {
   C++; B += C;
   u32bit X, Y;

   for(u32bit j = 0; j != 256; j += 4)
      {
      A ^= (A << 13);
      X = state[j];
      A += state[(j+128) % 256];
      state[j] = Y = state[(X >> 2) & 0xFF] + A + B;
      X = B = state[(Y >> 10) & 0xFF] + X;
      buffer[4*j+ 0] = get_byte(0, X); buffer[4*j+ 1] = get_byte(1, X);
      buffer[4*j+ 2] = get_byte(2, X); buffer[4*j+ 3] = get_byte(3, X);

      A ^= (A >> 6);
      X = state[j+1];
      A += state[(j+129) % 256];
      state[j+1] = Y = state[(X >> 2) & 0xFF] + A + B;
      X = B = state[(Y >> 10) & 0xFF] + X;
      buffer[4*j+ 4] = get_byte(0, X); buffer[4*j+ 5] = get_byte(1, X);
      buffer[4*j+ 6] = get_byte(2, X); buffer[4*j+ 7] = get_byte(3, X);

      A ^= (A << 2);
      X = state[j+2];
      A += state[(j+130) % 256];
      state[j+2] = Y = state[(X >> 2) & 0xFF] + A + B;
      X = B = state[(Y >> 10) & 0xFF] + X;
      buffer[4*j+ 8] = get_byte(0, X); buffer[4*j+ 9] = get_byte(1, X);
      buffer[4*j+10] = get_byte(2, X); buffer[4*j+11] = get_byte(3, X);

      A ^= (A >> 16);
      X = state[j+3];
      A += state[(j+131) % 256];
      state[j+3] = Y = state[(X >> 2) & 0xFF] + A + B;
      X = B = state[(Y >> 10) & 0xFF] + X;
      buffer[4*j+12] = get_byte(0, X); buffer[4*j+13] = get_byte(1, X);
      buffer[4*j+14] = get_byte(2, X); buffer[4*j+15] = get_byte(3, X);
      }
   position = 0;
   }

/*************************************************
* ISAAC Key Schedule                             *
*************************************************/
void ISAAC::key(const byte key[], u32bit length)
   {
   clear();

   for(u32bit j = 0; j != 256; j++)
      state[j] = make_u32bit(key[(4*j  )%length], key[(4*j+1)%length],
                             key[(4*j+2)%length], key[(4*j+3)%length]);

   u32bit A = 0x1367DF5A, B = 0x95D90059, C = 0xC3163E4B, D = 0x0F421AD8,
          E = 0xD92A4A78, F = 0xA51A3C49, G = 0xC4EFEA1B, H = 0x30609119;

   for(u32bit j = 0; j != 2; j++)
      for(u32bit l = 0; l != 256; l += 8)
         {
         A += state[l  ]; B += state[l+1]; C += state[l+2]; D += state[l+3];
         E += state[l+4]; F += state[l+5]; G += state[l+6]; H += state[l+7];
         A ^= (B << 11); D += A; B += C; B ^= (C >>  2); E += B; C += D;
         C ^= (D <<  8); F += C; D += E; D ^= (E >> 16); G += D; E += F;
         E ^= (F << 10); H += E; F += G; F ^= (G >>  4); A += F; G += H;
         G ^= (H <<  8); B += G; H += A; H ^= (A >>  9); C += H; A += B;
         state[l  ] = A; state[l+1] = B; state[l+2] = C; state[l+3] = D;
         state[l+4] = E; state[l+5] = F; state[l+6] = G; state[l+7] = H;
         }
   generate();
   generate();
   }

/*************************************************
* Clear memory of sensitive data                 *
*************************************************/
void ISAAC::clear() throw()
   {
   state.clear();
   buffer.clear();
   A = B = C = position = 0;
   }

}
