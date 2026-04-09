#pragma once
#include <stdint.h>
#include <string.h>

// Keccak-256 — used by Ethereum for address derivation and tx hashing.
// NOTE: This is NOT NIST SHA3-256. They differ only in padding:
//   Keccak uses 0x01, NIST SHA3 uses 0x06.

static const uint64_t KECCAK_RC[24] = {
  0x0000000000000001ULL, 0x0000000000008082ULL,
  0x800000000000808aULL, 0x8000000080008000ULL,
  0x000000000000808bULL, 0x0000000080000001ULL,
  0x8000000080008081ULL, 0x8000000000008009ULL,
  0x000000000000008aULL, 0x0000000000000088ULL,
  0x0000000080008009ULL, 0x000000008000000aULL,
  0x000000008000808bULL, 0x800000000000008bULL,
  0x8000000000008089ULL, 0x8000000000008003ULL,
  0x8000000000008002ULL, 0x8000000000000080ULL,
  0x000000000000800aULL, 0x800000008000000aULL,
  0x8000000080008081ULL, 0x8000000000008080ULL,
  0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int KECCAK_ROTC[24] = {
  1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
  27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const int KECCAK_PILN[24] = {
  10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
  15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static inline uint64_t _rotl64(uint64_t x, int n) {
  return (x << n) | (x >> (64 - n));
}

static void keccak_f1600(uint64_t st[25]) {
  uint64_t bc[5], t;
  for (int r = 0; r < 24; r++) {
    // Theta
    for (int i = 0; i < 5; i++)
      bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];
    for (int i = 0; i < 5; i++) {
      t = bc[(i+4)%5] ^ _rotl64(bc[(i+1)%5], 1);
      for (int j = 0; j < 25; j += 5) st[j+i] ^= t;
    }
    // Rho Pi
    t = st[1];
    for (int i = 0; i < 24; i++) {
      int j = KECCAK_PILN[i];
      bc[0] = st[j];
      st[j] = _rotl64(t, KECCAK_ROTC[i]);
      t = bc[0];
    }
    // Chi
    for (int j = 0; j < 25; j += 5) {
      for (int i = 0; i < 5; i++) bc[i] = st[j+i];
      for (int i = 0; i < 5; i++) st[j+i] ^= (~bc[(i+1)%5]) & bc[(i+2)%5];
    }
    // Iota
    st[0] ^= KECCAK_RC[r];
  }
}

// Compute Keccak-256 of `inlen` bytes at `in`, write 32 bytes to `out`.
static void keccak256(const uint8_t *in, size_t inlen, uint8_t *out) {
  const int RATE = 136; // (1600 - 256*2) / 8
  uint64_t st[25];
  uint8_t  tmp[136];
  memset(st, 0, sizeof(st));

  // Absorb full blocks
  while (inlen >= (size_t)RATE) {
    for (int i = 0; i < RATE; i += 8) {
      uint64_t w = 0;
      for (int b = 0; b < 8; b++) w |= (uint64_t)in[i+b] << (8*b);
      st[i/8] ^= w;
    }
    keccak_f1600(st);
    in    += RATE;
    inlen -= RATE;
  }

  // Final block with Keccak padding (0x01, not 0x06)
  memset(tmp, 0, RATE);
  memcpy(tmp, in, inlen);
  tmp[inlen]    ^= 0x01;
  tmp[RATE - 1] ^= 0x80;
  for (int i = 0; i < RATE; i += 8) {
    uint64_t w = 0;
    for (int b = 0; b < 8; b++) w |= (uint64_t)tmp[i+b] << (8*b);
    st[i/8] ^= w;
  }
  keccak_f1600(st);

  // Squeeze 32 bytes (little-endian words → bytes)
  for (int i = 0; i < 4; i++)
    for (int b = 0; b < 8; b++)
      out[i*8+b] = (st[i] >> (8*b)) & 0xFF;
}