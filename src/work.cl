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

constant uint blake2b_sigma[12][16] = {
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
};

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

static inline ulong2 rotr64(ulong2 v, uint i)
{
#ifdef cl_amd_media_ops
#pragma OPENCL EXTENSION cl_amd_media_ops : enable
    uint4 v4 = as_uint4(v);
    if (i < 32) {
        return as_ulong2(amd_bitalign(v4.yx, v4, i));
    } else {
        return as_ulong2(amd_bitalign(v4, v4.yx, (i - 32)));
    }
#else
    return rotate(v, (ulong2)(64UL - i));
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

static inline void ROUND(ulong2* v, ulong2* m, constant uint* i)
{
    G(v[0], v[4], v[8], v[12], m[i[0]], m[i[1]]);
    G(v[1], v[5], v[9], v[13], m[i[2]], m[i[3]]);
    G(v[2], v[6], v[10], v[14], m[i[4]], m[i[5]]);
    G(v[3], v[7], v[11], v[15], m[i[6]], m[i[7]]);

    G(v[0], v[5], v[10], v[15], m[i[8]], m[i[9]]);
    G(v[1], v[6], v[11], v[12], m[i[10]], m[i[11]]);
    G(v[2], v[7], v[8], v[13], m[i[12]], m[i[13]]);
    G(v[3], v[4], v[9], v[14], m[i[14]], m[i[15]]);
}

static inline ulong2 blake2b(const ulong2 n, __constant ulong* h)
{
    ulong2 v[16] = {
        IV_PARAM, IV_1, IV_2, IV_3, IV_4, IV_5, IV_6, IV_7,
        IV_0, IV_1, IV_2, IV_3, IV_INLEN, IV_5, IV_FINAL, IV_7
    };

    // ulong2 v[] = {
    //     (ulong2)IV_PARAM, (ulong2)IV_1, (ulong2)IV_2, (ulong2)IV_3, (ulong2)IV_4, (ulong2)IV_5, (ulong2)IV_6, (ulong2)IV_7,
    //     (ulong2)IV_0, (ulong2)IV_1, (ulong2)IV_2, (ulong2)IV_3, (ulong2)IV_INLEN, (ulong2)IV_5, (ulong2)IV_FINAL, (ulong2)IV_7
    // };
    ulong2 m[16] = {
        n, h[0], h[1], h[2], h[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    ROUND(v, m, blake2b_sigma[0]);
    ROUND(v, m, blake2b_sigma[1]);
    ROUND(v, m, blake2b_sigma[2]);
    ROUND(v, m, blake2b_sigma[3]);
    ROUND(v, m, blake2b_sigma[4]);
    ROUND(v, m, blake2b_sigma[5]);
    ROUND(v, m, blake2b_sigma[6]);
    ROUND(v, m, blake2b_sigma[7]);
    ROUND(v, m, blake2b_sigma[8]);
    ROUND(v, m, blake2b_sigma[9]);
    ROUND(v, m, blake2b_sigma[10]);
    ROUND(v, m, blake2b_sigma[11]);
    return (ulong2)IV_PARAM ^ v[0] ^ v[8];
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
    const ulong2 m0 = (ulong2)(nonce, nonce | 0x8000000000000000);

    const ulong2 result = blake2b(m0, item_a);
    if (result.s0 >= difficulty)
        *result_a = m0.s0;
    if (result.s1 >= difficulty)
        *result_a = m0.s1;
}
