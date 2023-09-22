/*
chet_sha256 - v2.0.0 - public domain sha2
    no warranty implied; use at your own risk
    supports c99 or later and should work with C++

    api calls begin with 'chet_' and please ignore identifiers beginning with 'ichet_' which are internal

API
    void chet_sha256(const void *input, size_t byte_length, uint8_t hash_result[32])

LICENSE
    See the end of this file for the license information.
*/

#ifndef CHET_SHA2__SHA256_H_INCLUDED
#define CHET_SHA2__SHA256_H_INCLUDED

#include <stdint.h>
#include <stddef.h>
#include <string.h>

static inline uint64_t ichet_sha2__swap_endian_64(uint64_t x)
{
    x = (x & 0x00000000FFFFFFFF) << 32 | (x & 0xFFFFFFFF00000000) >> 32;
    x = (x & 0x0000FFFF0000FFFF) << 16 | (x & 0xFFFF0000FFFF0000) >> 16;
    x = (x & 0x00FF00FF00FF00FF) << 8  | (x & 0xFF00FF00FF00FF00) >> 8;
    return x;
}

static inline uint64_t ichet_sha2__div_round_up(uint64_t value, size_t align)
{
    return (value + align - 1) / align;
}

static inline void ichet_sha2__pack_u32(uint32_t src, uint8_t *dest)
{
    dest[0] = (src & 0xFF000000) >> 24;
    dest[1] = (src & 0x00FF0000) >> 16;
    dest[2] = (src & 0x0000FF00) >>  8;
    dest[3] = (src & 0x000000FF);
}

#define ichet_sha2__choose(x, y, z) ((x & y) ^ ((~x) & z))
#define ichet_sha2__majority(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define ichet_sha2__rotr(x, n) ((x >> n) | (x << (32 - n)))
#define ichet_sha2__SIGMA_0(x) (ichet_sha2__rotr(x, 2) ^ ichet_sha2__rotr(x, 13) ^ ichet_sha2__rotr(x, 22))
#define ichet_sha2__SIGMA_1(x) (ichet_sha2__rotr(x, 6) ^ ichet_sha2__rotr(x, 11) ^ ichet_sha2__rotr(x, 25))
#define ichet_sha2__sigma_0(x) (ichet_sha2__rotr(x, 7) ^ ichet_sha2__rotr(x, 18) ^ (x >> 3))
#define ichet_sha2__sigma_1(x) (ichet_sha2__rotr(x, 17) ^ ichet_sha2__rotr(x, 19) ^ (x >> 10))

/* `input` will have `byte_length` bytes hashed, this doesn't hash bit lengths */
static inline void chet_sha256(const void *input, size_t byte_length, uint8_t hash_result[32])
{
    uint32_t H0 = 0x6a09e667;
    uint32_t H1 = 0xbb67ae85;
    uint32_t H2 = 0x3c6ef372;
    uint32_t H3 = 0xa54ff53a;
    uint32_t H4 = 0x510e527f;
    uint32_t H5 = 0x9b05688c;
    uint32_t H6 = 0x1f83d9ab;
    uint32_t H7 = 0x5be0cd19;

    static const uint32_t k_const[64] =
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    /* create space for two chunks to handle the case where the padding size exceeds the 512 bit boundary */
    uint8_t final_chunks[128] = {0};
    const uint8_t *data = (const uint8_t *)input;

    /* explicitly use a 64 bit type in case of overflow on machines that use 32 bits for size_t */
    uint64_t bit_length = (uint64_t)byte_length * 8;
    size_t full_chunks = bit_length / 512;

    /* determine the total number of chunks considering extra 1 bit and 64 bits for length. */
    size_t total_chunks = ichet_sha2__div_round_up(bit_length + 1 + 64, 512);
    size_t number_final_chunks = total_chunks - full_chunks;

    size_t bit_remainder = bit_length % 512;
    size_t padding_bytes = (number_final_chunks * 64) - (bit_remainder / 8);

    size_t final_chunks_byte_length = number_final_chunks * 64;

    uint32_t w_schedule[64] = {0};
    size_t chunk = 0;

    uint64_t encoded_length = ichet_sha2__swap_endian_64(bit_length);

    /* create the final chunk / padded chunk */
    memcpy(&final_chunks[0], &data[full_chunks * 64], bit_remainder / 8);
    final_chunks[final_chunks_byte_length - padding_bytes] = 1 << 7; /* append a byte disguised as a single bit */
    memcpy(&final_chunks[final_chunks_byte_length - sizeof(encoded_length)], &encoded_length, sizeof(encoded_length));

    while (chunk < (full_chunks + number_final_chunks))
    {
        size_t word;
        size_t tdx;

        /* detect if we are processing the last (padded) chunk(s) */
        if (chunk == full_chunks)
        {
            data = (const uint8_t *)final_chunks; /* switch to processing final_chunks */
        }

        /* 1. */
        for (word = 0; word < 16; ++word)
        {
            w_schedule[word] = (uint32_t)(data[word * 4])     << 24 |
                               (uint32_t)(data[word * 4 + 1]) << 16 |
                               (uint32_t)(data[word * 4 + 2]) <<  8 |
                               (uint32_t)(data[word * 4 + 3]);
        }
        for (word = 16; word < 64; ++word)
        {
            w_schedule[word] = ichet_sha2__sigma_1(w_schedule[word - 2]) + w_schedule[word - 7] +
                ichet_sha2__sigma_0(w_schedule[word - 15]) + w_schedule[word - 16];
        }

        /* 2. */
        uint32_t a = H0;
        uint32_t b = H1;
        uint32_t c = H2;
        uint32_t d = H3;
        uint32_t e = H4;
        uint32_t f = H5;
        uint32_t g = H6;
        uint32_t h = H7;

        /* 3. */
        for (tdx = 0; tdx < 64; ++tdx)
        {
            uint32_t T1 = h + ichet_sha2__SIGMA_1(e) + ichet_sha2__choose(e, f, g) + k_const[tdx] + w_schedule[tdx];
            uint32_t T2 = ichet_sha2__SIGMA_0(a) + ichet_sha2__majority(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        /* 4. */
        H0 += a;
        H1 += b;
        H2 += c;
        H3 += d;
        H4 += e;
        H5 += f;
        H6 += g;
        H7 += h;

        data += 64;
        chunk++;
    }

    ichet_sha2__pack_u32(H0, hash_result); hash_result += 4;
    ichet_sha2__pack_u32(H1, hash_result); hash_result += 4;
    ichet_sha2__pack_u32(H2, hash_result); hash_result += 4;
    ichet_sha2__pack_u32(H3, hash_result); hash_result += 4;
    ichet_sha2__pack_u32(H4, hash_result); hash_result += 4;
    ichet_sha2__pack_u32(H5, hash_result); hash_result += 4;
    ichet_sha2__pack_u32(H6, hash_result); hash_result += 4;
    ichet_sha2__pack_u32(H7, hash_result);
}

#endif

/*
------------------------------------------------------------------------------
This software is available under 2 licenses -- choose whichever you prefer.
------------------------------------------------------------------------------
ALTERNATIVE A - MIT License
Copyright (c) 2023 Justin "Chetco" Brown
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
------------------------------------------------------------------------------
ALTERNATIVE B - Public Domain (www.unlicense.org)
This is free and unencumbered software released into the public domain.
Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
software, either in source code form or as a compiled binary, for any purpose,
commercial or non-commercial, and by any means.
In jurisdictions that recognize copyright laws, the author or authors of this
software dedicate any and all copyright interest in the software to the public
domain. We make this dedication for the benefit of the public at large and to
the detriment of our heirs and successors. We intend this dedication to be an
overt act of relinquishment in perpetuity of all present and future rights to
this software under copyright law.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
------------------------------------------------------------------------------
*/
