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
static inline ulong4 rotr64(ulong4 x, int shift)
{
    uint8 x8 = as_uint8(x);
    if (shift < 32)
        return as_ulong4(amd_bitalign(x8.s10325476, x8, shift));
    return as_ulong4(amd_bitalign(x8, x8.s10325476, (shift - 32)));
}
#else
static inline ulong4 rotr64(ulong4 x, int shift)
{
    return rotate(x, (ulong4)(64UL - shift));
}
#endif

#define G(a, b, c, d, x, y)    \
    do {                       \
        a += b + x;            \
        d = rotr64(d ^ a, 32); \
        c += d;                \
        b = rotr64(b ^ c, 24); \
        a += b + y;            \
        d = rotr64(d ^ a, 16); \
        c += d;                \
        b = rotr64(b ^ c, 63); \
    } while (0)

#define ROUND(m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, mA, mB, mC, mD, mE, mF) \
    do {                                                                      \
        G(v.s0123, v.s4567, v.s89AB, v.sCDEF, (ulong4)(m0, m2, m4, m6),       \
            (ulong4)(m1, m3, m5, m7));                                        \
        G(v.s0123, v.s5674, v.sAB89, v.sFCDE, (ulong4)(m8, mA, mC, mE),       \
            (ulong4)(m9, mB, mD, mF));                                        \
    } while (0)

// n: nonce
// h: block hash
static inline ulong blake2b(ulong const n, __constant ulong* h)
{
    ulong16 v = { IV_0, IV_1, IV_2, IV_3,
        IV_4, IV_5, IV_6, IV_7,
        IV_8, IV_9, IV_10, IV_11,
        IV_12, IV_13, IV_14, IV_15 };

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

    return IV_0 ^ v.s0 ^ v.s8;
}
#undef G
#undef ROUND

__kernel void nano_work(__constant ulong* attempt,
    __global ulong* result_a,
    __constant ulong* item_a,
    const ulong difficulty)
{
    const ulong attempt_l = *attempt + get_global_id(0);
    if (blake2b(attempt_l, item_a) >= difficulty)
        *result_a = attempt_l;
}
