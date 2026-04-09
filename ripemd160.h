#pragma once
#include <stdint.h>
#include <string.h>

// Standalone RIPEMD-160 implementation.
// Call: ripemd160(input, length, output_20_bytes)

#define RMD_F(x,y,z) ((x)^(y)^(z))
#define RMD_G(x,y,z) (((x)&(y))|(~(x)&(z)))
#define RMD_H(x,y,z) (((x)|(~(y)))^(z))
#define RMD_I(x,y,z) (((x)&(z))|((y)&(~(z))))
#define RMD_J(x,y,z) ((x)^((y)|(~(z))))
#define ROL32(x,n)   (((x)<<(n))|((x)>>(32-(n))))

static const uint32_t RMD_KL[5] = {0x00000000,0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xA953FD4E};
static const uint32_t RMD_KR[5] = {0x50A28BE6,0x5C4DD124,0x6D703EF3,0x7A6D76E9,0x00000000};

static const int RMD_RL[80] = {
  11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8,
   7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12,
  11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5,
  11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8, 6, 5,12,
   9,15, 5,11, 6, 8,13,12, 5,12,13,14,11, 8, 5, 6
};
static const int RMD_RR[80] = {
   8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6,
   9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11,
   9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5,
  15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8,
   8, 5,12, 9,12, 5,14, 6, 8,13, 6, 5,15,13,11,11
};
static const int RMD_ML[80] = {
   0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
   7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8,
   3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12,
   1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2,
   4, 0, 5, 9, 7,12, 2,10,14, 1, 3, 8,11, 6,15,13
};
static const int RMD_MR[80] = {
   5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12,
   6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2,
  15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13,
   8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14,
  12,15,10, 4, 1, 5, 8, 7, 6, 2,13,14, 0, 3, 9,11
};

static void rmd_compress(uint32_t state[5], const uint8_t block[64]) {
  uint32_t X[16];
  for (int i = 0; i < 16; i++)
    X[i] = (uint32_t)block[i*4]|(uint32_t)block[i*4+1]<<8|
            (uint32_t)block[i*4+2]<<16|(uint32_t)block[i*4+3]<<24;

  uint32_t al=state[0],bl=state[1],cl=state[2],dl=state[3],el=state[4];
  uint32_t ar=state[0],br=state[1],cr=state[2],dr=state[3],er=state[4];
  uint32_t t;

  for (int i = 0; i < 80; i++) {
    int r = i / 16;
    uint32_t fl, fr;
    switch (r) {
      case 0: fl=RMD_F(bl,cl,dl); fr=RMD_J(br,cr,dr); break;
      case 1: fl=RMD_G(bl,cl,dl); fr=RMD_I(br,cr,dr); break;
      case 2: fl=RMD_H(bl,cl,dl); fr=RMD_H(br,cr,dr); break;
      case 3: fl=RMD_I(bl,cl,dl); fr=RMD_G(br,cr,dr); break;
      default:fl=RMD_J(bl,cl,dl); fr=RMD_F(br,cr,dr); break;
    }
    t = ROL32(al+fl+X[RMD_ML[i]]+RMD_KL[r], RMD_RL[i])+el;
    al=el; el=dl; dl=ROL32(cl,10); cl=bl; bl=t;
    t = ROL32(ar+fr+X[RMD_MR[i]]+RMD_KR[r], RMD_RR[i])+er;
    ar=er; er=dr; dr=ROL32(cr,10); cr=br; br=t;
  }

  t=state[1]+cl+dr; state[1]=state[2]+dl+er; state[2]=state[3]+el+ar;
  state[3]=state[4]+al+br; state[4]=state[0]+bl+cr; state[0]=t;
}

static void ripemd160(const uint8_t *msg, size_t len, uint8_t out[20]) {
  uint32_t state[5] = {0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0};
  uint8_t  block[64];
  size_t   rem = len;
  const uint8_t *p = msg;

  // Process full blocks
  while (rem >= 64) {
    rmd_compress(state, p);
    p += 64; rem -= 64;
  }

  // Final block(s)
  memset(block, 0, 64);
  memcpy(block, p, rem);
  block[rem] = 0x80;

  if (rem >= 56) {
    rmd_compress(state, block);
    memset(block, 0, 64);
  }

  uint64_t bitlen = (uint64_t)len * 8;
  for (int i = 0; i < 8; i++)
    block[56+i] = (bitlen >> (8*i)) & 0xFF;
  rmd_compress(state, block);

  for (int i = 0; i < 5; i++) {
    out[i*4+0] =  state[i]        & 0xFF;
    out[i*4+1] = (state[i] >>  8) & 0xFF;
    out[i*4+2] = (state[i] >> 16) & 0xFF;
    out[i*4+3] = (state[i] >> 24) & 0xFF;
  }
}