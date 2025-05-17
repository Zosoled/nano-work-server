/**
 * BLAKE2b initialization
 *
 * param block: 0x01010008 (depth = 1, fanout = 1, digest byte length = 8)
 * input length: 0x28 (40 bytes)
 * digest finalization flag: 0xffffffffffffffffUL (~0)
 */
enum BLAKE2B_IV {
    IV_0 = 0x6a09e667f3bcc908UL,
    IV_1 = 0xbb67ae8584caa73bUL,
    IV_2 = 0x3c6ef372fe94f82bUL,
    IV_3 = 0xa54ff53a5f1d36f1UL,
    IV_4 = 0x510e527fade682d1UL,
    IV_5 = 0x9b05688c2b3e6c1fUL,
    IV_6 = 0x1f83d9abfb41bd6bUL,
    IV_7 = 0x5be0cd19137e2179UL,
    IV_PARAM = 0x6a09e667f2bdc900UL, // 0x6a09e667f3bcc908UL ^ PARAM
    IV_INLEN = 0x510e527fade682f9UL, // 0x510e527fade682d1UL ^ INLEN
    IV_FINAL = 0xe07c265404be4294UL, // 0x1f83d9abfb41bd6bUL ^ DIGEST
};

#ifdef cl_amd_media_ops
#pragma OPENCL EXTENSION cl_amd_media_ops : enable
static inline ulong rotr64(ulong v, uchar i)
{
    uint2 vv = as_uint2(v);
    if (i < 32) {
        return as_ulong(amd_bitalign(vv.yx, vv, i));
    } else {
        return as_ulong(amd_bitalign(vv, vv.yx, (i - 32)));
    }
}
#else
#define rotr64(v, i) rotate(v, 64UL - i##UL)
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
        G(v0, v4, v8, vC, m0, m1);                                            \
        G(v1, v5, v9, vD, m2, m3);                                            \
        G(v2, v6, vA, vE, m4, m5);                                            \
        G(v3, v7, vB, vF, m6, m7);                                            \
                                                                              \
        G(v0, v5, vA, vF, m8, m9);                                            \
        G(v1, v6, vB, vC, mA, mB);                                            \
        G(v2, v7, v8, vD, mC, mD);                                            \
        G(v3, v4, v9, vE, mE, mF);                                            \
    } while (0)

// n: nonce
// h: block hash
static inline ulong blake2b(ulong const n, __constant ulong* h)
{
    ulong v0 = IV_PARAM;
    ulong v1 = IV_1;
    ulong v2 = IV_2;
    ulong v3 = IV_3;
    ulong v4 = IV_4;
    ulong v5 = IV_5;
    ulong v6 = IV_6;
    ulong v7 = IV_7;
    ulong v8 = IV_0;
    ulong v9 = IV_1;
    ulong vA = IV_2;
    ulong vB = IV_3;
    ulong vC = IV_INLEN;
    ulong vD = IV_5;
    ulong vE = IV_FINAL;
    ulong vF = IV_7;

    ulong m0 = n;
    ulong m1 = h[0];
    ulong m2 = h[1];
    ulong m3 = h[2];
    ulong m4 = h[3];

    ROUND(m0, m1, m2, m3, m4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    ROUND(0, 0, m4, 0, 0, 0, 0, 0, m1, 0, m0, m2, 0, 0, 0, m3);
    ROUND(0, 0, 0, m0, 0, m2, 0, 0, 0, 0, m3, 0, 0, m1, 0, m4);
    ROUND(0, 0, m3, m1, 0, 0, 0, 0, m2, 0, 0, 0, m4, m0, 0, 0);
    ROUND(0, m0, 0, 0, m2, m4, 0, 0, 0, m1, 0, 0, 0, 0, m3, 0);
    ROUND(m2, 0, 0, 0, m0, 0, 0, m3, m4, 0, 0, 0, 0, 0, m1, 0);
    ROUND(0, 0, m1, 0, 0, 0, m4, 0, m0, 0, 0, m3, 0, m2, 0, 0);
    ROUND(0, 0, 0, 0, 0, m1, m3, 0, 0, m0, 0, m4, 0, 0, m2, 0);
    ROUND(0, 0, 0, 0, 0, m3, m0, 0, 0, m2, 0, 0, m1, m4, 0, 0);
    ROUND(0, m2, 0, m4, 0, 0, m1, 0, 0, 0, 0, 0, m3, 0, 0, m0);
    ROUND(m0, m1, m2, m3, m4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    ROUND(0, 0, m4, 0, 0, 0, 0, 0, m1, 0, m0, m2, 0, 0, 0, m3);

    return IV_0 ^ v0 ^ v8;
}
#undef G
#undef ROUND

__kernel void work_generate(
    __global uchar* work,
    __constant uchar* seed,
    __constant uchar* hash,
    const ulong difficulty)
{
    const ulong nonce = *((__constant ulong*)seed) + get_global_id(0);
    if (blake2b(nonce, (__constant ulong*)hash) >= difficulty) {
        *((__global ulong*)work) = nonce;
    }
}
