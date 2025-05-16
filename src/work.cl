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

enum BLAKE2B_IV {
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
        return as_ulong4(amd_bitalign(v8.s10325476, v8, i));
    } else {
        return as_ulong4(amd_bitalign(v8, v8.s10325476, (i - 32)));
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

static inline void ROUND(ulong16* v, ulong16 m)
{
    G((*v).s0123, (*v).s4567, (*v).s89AB, (*v).sCDEF, m.s0246, m.s1357);
    G((*v).s0123, (*v).s5674, (*v).sAB89, (*v).sFCDE, m.s8ACE, m.s9BDF);
}

static inline ulong blake2b(const ulong n, __constant ulong* h)
{
    ulong16 v = {
        IV_PARAM, IV_1, IV_2, IV_3, IV_4, IV_5, IV_6, IV_7,
        IV_0, IV_1, IV_2, IV_3, IV_INLEN, IV_5, IV_FINAL, IV_7
    };
    ulong16 m = {
        n, h[0], h[1], h[2], h[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    ROUND(&v, m.s0123456789ABCDEF);
    ROUND(&v, m.sEA489FD61C02B753);
    ROUND(&v, m.sB8C052FDAE367194);
    ROUND(&v, m.s7931DCBE265A40F8);
    ROUND(&v, m.s905724AFE1BC683D);
    ROUND(&v, m.s2C6A0B834D75FE19);
    ROUND(&v, m.sC51FED4A0763928B);
    ROUND(&v, m.sDB7EC13950F4862A);
    ROUND(&v, m.s6FE9B308C2D714A5);
    ROUND(&v, m.sA2847615FB9E3CD0);
    ROUND(&v, m.s0123456789ABCDEF);
    ROUND(&v, m.sEA489FD61C02B753);
    return IV_0 ^ v.s0 ^ v.s8;
}

#undef G
#undef ROUND

__kernel void work_generate(
    __constant uchar* seed,
    __constant uchar* blockhash,
    __global uchar* work,
    const ulong difficulty)
{
    if (*(volatile __global ulong*)work != 0) {
        return;
    }
    const ulong nonce = *(__constant ulong*)seed + get_global_id(0);
    const ulong hash = blake2b(nonce, (__constant ulong*)blockhash);
    if (hash >= difficulty) {
        *((__global ulong*)work) = nonce;
    }
}
