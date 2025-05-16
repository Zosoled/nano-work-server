/**
 * Nano PoW OpenCL kernel (BLAKE2b)
 *
 * Each thread concatenates a unique nonce with the blockhash and uses the
 * BLAKE2b hash algorithm to produces an 8-byte work result. If the result is
 * greater than or equal to the difficulty value, it is atomically written to a
 * global buffer to be read by the CPU.
 *
 * BLAKE2b initialization:
 * Param block: 0x01010008 (depth = 1, fanout = 1, digest byte length = 8)
 * Input length: 0x28 (40 bytes)
 * Final block flag: 0xffffffffffffffffUL (~0)
 */

enum blake2b_iv {
    IV_0 = 0x6a09e667f3bcc908UL,
    IV_1 = 0xbb67ae8584caa73bUL,
    IV_2 = 0x3c6ef372fe94f82bUL,
    IV_3 = 0xa54ff53a5f1d36f1UL,
    IV_4 = 0x510e527fade682d1UL,
    IV_5 = 0x9b05688c2b3e6c1fUL,
    IV_6 = 0x1f83d9abfb41bd6bUL,
    IV_7 = 0x5be0cd19137e2179UL,
    IV_PARAM = 0x6a09e667f2bdc900UL, // IV_0 ^ PARAM
    IV_INLEN = 0x510e527fade682f9UL, // IV_4 ^ 40
    IV_FINAL = 0xe07c265404be4294UL, // IV_6 ^ ~0
};

static inline ulong4 rotr64(ulong4 v, uint i)
{
#ifdef cl_amd_media_ops
#pragma OPENCL EXTENSION cl_amd_media_ops : enable
    uint8 v8 = as_uint8(v);
    if (i < 32) {
        return as_ulong4(amd_bitalign(v8.yx, v8, i));
    } else {
        return as_ulong4(amd_bitalign(v8, v8.yx, (i - 32)));
    }
#else
    return rotate(v, (ulong4)(64UL - i));
#endif
}

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
        G(v0, v4, v8, v12, m##m0, m##m1);                                     \
        G(v1, v5, v9, v13, m##m2, m##m3);                                     \
        G(v2, v6, v10, v14, m##m4, m##m5);                                    \
        G(v3, v7, v11, v15, m##m6, m##m7);                                    \
                                                                              \
        G(v0, v5, v10, v15, m##m8, m##m9);                                    \
        G(v1, v6, v11, v12, m##mA, m##mB);                                    \
        G(v2, v7, v8, v13, m##mC, m##mD);                                     \
        G(v3, v4, v9, v14, m##mE, m##mF);                                     \
    } while (0)

static inline ulong4 blake2b(const ulong4 n, __constant ulong* h)
{
    ulong4 v0 = (ulong4)IV_PARAM;
    ulong4 v1 = (ulong4)IV_1;
    ulong4 v2 = (ulong4)IV_2;
    ulong4 v3 = (ulong4)IV_3;
    ulong4 v4 = (ulong4)IV_4;
    ulong4 v5 = (ulong4)IV_5;
    ulong4 v6 = (ulong4)IV_6;
    ulong4 v7 = (ulong4)IV_7;
    ulong4 v8 = (ulong4)IV_0;
    ulong4 v9 = (ulong4)IV_1;
    ulong4 v10 = (ulong4)IV_2;
    ulong4 v11 = (ulong4)IV_3;
    ulong4 v12 = (ulong4)IV_INLEN;
    ulong4 v13 = (ulong4)IV_5;
    ulong4 v14 = (ulong4)IV_FINAL;
    ulong4 v15 = (ulong4)IV_7;

    ulong4 m0 = n;
    ulong4 m1 = (ulong4)h[0];
    ulong4 m2 = (ulong4)h[1];
    ulong4 m3 = (ulong4)h[2];
    ulong4 m4 = (ulong4)h[3];
    ulong4 m5 = (ulong4)0;
    ulong4 m6 = (ulong4)0;
    ulong4 m7 = (ulong4)0;
    ulong4 m8 = (ulong4)0;
    ulong4 m9 = (ulong4)0;
    ulong4 m10 = (ulong4)0;
    ulong4 m11 = (ulong4)0;
    ulong4 m12 = (ulong4)0;
    ulong4 m13 = (ulong4)0;
    ulong4 m14 = (ulong4)0;
    ulong4 m15 = (ulong4)0;

    ROUND(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    ROUND(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
    ROUND(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4);
    ROUND(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8);
    ROUND(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13);
    ROUND(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9);
    ROUND(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11);
    ROUND(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10);
    ROUND(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5);
    ROUND(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0);
    ROUND(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    ROUND(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);

    return (ulong4)IV_PARAM ^ v0 ^ v8;
}

#undef G
#undef ROUND

__kernel void nano_work(
    __constant ulong* seed,
    __global ulong* result_a,
    __constant ulong* item_a,
    const ulong difficulty)
{
    const ulong nonce = *seed + get_global_id(0);
    const ulong4 m0 = (ulong4)(nonce, nonce | 0x4000000000000000, nonce | 0x8000000000000000, nonce | 0xC000000000000000);

    const ulong4 result = blake2b(nonce, item_a);
    if (result.s0 >= difficulty)
        *result_a = m0.s0;
    if (result.s1 >= difficulty)
        *result_a = m0.s1;
    if (result.s2 >= difficulty)
        *result_a = m0.s2;
    if (result.s3 >= difficulty)
        *result_a = m0.s3;
}
