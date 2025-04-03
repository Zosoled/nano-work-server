/**
 * BLAKE2b initialization
 *
 * param block: 0x01010008 (depth = 1, fanout = 1, digest byte length = 8)
 * input length: 0x28 (40 bytes)
 * digest finalization flag: 0xffffffffffffffffUL (~0)
 */
enum BLAKE2B_IV {
  IV_0 = 0x6a09e667f2bdc900UL, // 0x6a09e667f3bcc908UL ^ PARAM
  IV_1 = 0xbb67ae8584caa73bUL,
  IV_2 = 0x3c6ef372fe94f82bUL,
  IV_3 = 0xa54ff53a5f1d36f1UL,
  IV_4 = 0x510e527fade682d1UL,
  IV_5 = 0x9b05688c2b3e6c1fUL,
  IV_6 = 0x1f83d9abfb41bd6bUL,
  IV_7 = 0x5be0cd19137e2179UL,
  IV_8 = 0x6a09e667f3bcc908UL,
  IV_9 = 0xbb67ae8584caa73bUL,
  IV_10 = 0x3c6ef372fe94f82bUL,
  IV_11 = 0xa54ff53a5f1d36f1UL,
  IV_12 = 0x510e527fade682f9UL, // 0x510e527fade682d1UL ^ INLEN
  IV_13 = 0x9b05688c2b3e6c1fUL,
  IV_14 = 0xe07c265404be4294UL, // 0x1f83d9abfb41bd6bUL ^ DIGEST
  IV_15 = 0x5be0cd19137e2179UL,
};

#ifdef cl_amd_media_ops
#pragma OPENCL EXTENSION cl_amd_media_ops : enable
static inline ulong rotr64(ulong x, int shift) {
  uint2 x2 = as_uint2(x);
  if (shift < 32)
    return as_ulong(amd_bitalign(x2.yx, x2, shift));
  return as_ulong(amd_bitalign(x2, x2.yx, (shift - 32)));
}
#else
static inline ulong rotr64(ulong x, int shift) {
  return rotate(x, (ulong)(64UL - shift));
}
#endif

ulong4 a;
ulong4 b;
ulong4 c;
ulong4 d;

#define G(a, b, c, d, x, y)                                                    \
  do {                                                                         \
    a += b + x;                                                                \
    d = rotr64(d ^ a, 32);                                                     \
    c += d;                                                                    \
    b = rotr64(b ^ c, 24);                                                     \
    a += b + y;                                                                \
    d = rotr64(d ^ a, 16);                                                     \
    c += d;                                                                    \
    b = rotr64(b ^ c, 63);                                                     \
  } while (0)

#define ROUND(m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, \
              m15)                                                             \
  do {                                                                         \
    G(v[0], v[4], v[8], v[12], m0, m1);                                        \
    G(v[1], v[5], v[9], v[13], m2, m3);                                        \
    G(v[2], v[6], v[10], v[14], m4, m5);                                       \
    G(v[3], v[7], v[11], v[15], m6, m7);                                       \
                                                                               \
    G(v[0], v[5], v[10], v[15], m8, m9);                                       \
    G(v[1], v[6], v[11], v[12], m10, m11);                                     \
    G(v[2], v[7], v[8], v[13], m12, m13);                                      \
    G(v[3], v[4], v[9], v[14], m14, m15);                                      \
  } while (0)

// n: nonce
// h: block hash
static inline ulong blake2b(ulong const n, __constant ulong *h) {
  ulong v[16] = {IV_0, IV_1, IV_2,  IV_3,  IV_4,  IV_5,  IV_6,  IV_7,
                 IV_8, IV_9, IV_10, IV_11, IV_12, IV_13, IV_14, IV_15};

  ROUND(n, h[0], h[1], h[2], h[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  ROUND(0, 0, h[3], 0, 0, 0, 0, 0, h[0], 0, n, h[1], 0, 0, 0, h[2]);
  ROUND(0, 0, 0, n, 0, h[1], 0, 0, 0, 0, h[2], 0, 0, h[0], 0, h[3]);
  ROUND(0, 0, h[2], h[0], 0, 0, 0, 0, h[1], 0, 0, 0, h[3], n, 0, 0);
  ROUND(0, n, 0, 0, h[1], h[3], 0, 0, 0, h[0], 0, 0, 0, 0, h[2], 0);
  ROUND(h[1], 0, 0, 0, n, 0, 0, h[2], h[3], 0, 0, 0, 0, 0, h[0], 0);
  ROUND(0, 0, h[0], 0, 0, 0, h[3], 0, n, 0, 0, h[2], 0, h[1], 0, 0);
  ROUND(0, 0, 0, 0, 0, h[0], h[2], 0, 0, n, 0, h[3], 0, 0, h[1], 0);
  ROUND(0, 0, 0, 0, 0, h[2], n, 0, 0, h[1], 0, 0, h[0], h[3], 0, 0);
  ROUND(0, h[1], 0, h[3], 0, 0, h[0], 0, 0, 0, 0, 0, h[2], 0, 0, n);
  ROUND(n, h[0], h[1], h[2], h[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  ROUND(0, 0, h[3], 0, 0, 0, 0, 0, h[0], 0, n, h[1], 0, 0, 0, h[2]);

  return IV_0 ^ v[0] ^ v[8];
}
#undef G
#undef ROUND

__kernel void nano_work(__constant ulong *attempt, __global ulong *result_a,
                        __constant ulong *item_a, const ulong difficulty) {
  const ulong attempt_l = *attempt + get_global_id(0);
  if (blake2b(attempt_l, item_a) >= difficulty)
    *result_a = attempt_l;
}
