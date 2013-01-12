/*
 Written in 2013 by Ulrik Sverdrup

 To the extent possible under law, the author(s) have dedicated all copyright
 and related and neighboring rights to this software to the public domain
 worldwide. This software is distributed without any warranty.

 You should have received a copy of the CC0 Public Domain Dedication along with
 this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include "blake2s.h"
#include "blake2s-internal.h"
#include <altivec.h>

typedef vector unsigned int   vu32;
typedef vector unsigned short vu16;
typedef vector unsigned char  vu8;

static const vu32 vr16 = {16,16,16,16};
static const vu32 vr12 = {20,20,20,20};
static const vu32 vr8  = {24,24,24,24};
static const vu32 vr7  = {25,25,25,25};

/* These are a combination of the BLAKE2 sigma(r) message word permutation
 * combined with a Zip even/odd permutation where
 * (a0 a1 a2 a3 ...) x (b0 b1 b2 b3 ..) -> (a0 b0 a2 b2 ...) */
static const vu8 blake2s_vsigma_even[10] =
{
    /*  G(m,.,) rows --->            G(m,.) diags ---> */
    { 0, 16,  2, 18,  4, 20,  6, 22,  8, 24, 10, 26, 12, 28, 14, 30},
    {14, 30,  4, 20,  9, 25, 13, 29,  1, 17,  0, 16, 11, 27,  5, 21},
    {11, 27, 12, 28,  5, 21, 15, 31, 10, 26,  3, 19,  7, 23,  9, 25},
    { 7, 23,  3, 19, 13, 29, 11, 27,  2, 18,  5, 21,  4, 20, 15, 31},
    { 9, 25,  5, 21,  2, 18, 10, 26, 14, 30, 11, 27,  6, 22,  3, 19},
    { 2, 18,  6, 22,  0, 16,  8, 24,  4, 20,  7, 23, 15, 31,  1, 17},
    {12, 28,  1, 17, 14, 30,  4, 20,  0, 16,  6, 22,  9, 25,  8, 24},
    {13, 29,  7, 23, 12, 28,  3, 19,  5, 21, 15, 31,  8, 24,  2, 18},
    { 6, 22, 14, 30, 11, 27,  0, 16, 12, 28, 13, 29,  1, 17, 10, 26},
    {10, 26,  8, 24,  7, 23,  1, 17, 15, 31,  9, 25,  3, 19, 13, 29},
};

static const vu8 blake2s_vsigma_odd[10] =
{
    /*  G(.,m) rows --->             G(.,m) diags ---> */
    { 1, 17,  3, 19,  5, 21,  7, 23,  9, 25, 11, 27, 13, 29, 15, 31},
    {10, 26,  8, 24, 15, 31,  6, 22, 12, 28,  2, 18,  7, 23,  3, 19},
    { 8, 24,  0, 16,  2, 18, 13, 29, 14, 30,  6, 22,  1, 17,  4, 20},
    { 9, 25,  1, 17, 12, 28, 14, 30,  6, 22, 10, 26,  0, 16,  8, 24},
    { 0, 16,  7, 23,  4, 20, 15, 31,  1, 17, 12, 28,  8, 24, 13, 29},
    {12, 28, 10, 26, 11, 27,  3, 19, 13, 29,  5, 21, 14, 30,  9, 25},
    { 5, 21, 15, 31, 13, 29, 10, 26,  7, 23,  3, 19,  2, 18, 11, 27},
    {11, 27, 14, 30,  1, 17,  9, 25,  0, 16,  4, 20,  6, 22, 10, 26},
    {15, 31,  9, 25,  3, 19,  8, 24,  2, 18,  7, 23,  4, 20,  5, 21},
    { 2, 18,  4, 20,  6, 22,  5, 21, 11, 27, 14, 30, 12, 28,  0, 16},
};

static const vu32 blake2s_viv[2] = {
    { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a },
    { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 },
};

static void blake2s_10rounds(vu32 va, vu32 vb, vu32 vc, vu32 vd,
                             vu32 H[2], const void *msg)
{
    /* 
     * The compression function state is 16 32-bit words.
     * Each column is a vector:
     *   va vb vc vd         va'vb'vc'vd'
     *  +--+--+--+--+       +--+--+--+--+
     *  | 0| 4| 8|12|       | 0| 5|10|15|
     *  +--+--+--+--+       +--+--+--+--+
     *  | 1| 5| 9|13|       | 1| 6|11|12|
     *  +--+--+ -+ -+       +--+--+--+--+
     *  | 2| 6|10|14|       | 2| 7| 8|13|
     *  +--+--+ -+ -+       +--+--+--+--+
     *  | 3| 7|11|15|       | 3| 4| 9|14|
     *  +-+-+-+-+-+-+       +-+-+-+-+-+-+
     *
     *  G(Columns)           G(Diagonals)
     *
     *  Since the function G() is applied on rows of this state,
     *  we can combine this into a parallel G(va,vb,vc,vd) evaluation.
     */

    /* Message schedule
     *
     * Byteslice the message:
     * Arrange the 16 message words transposed into 4 vectors x 16 bytes
     *
     * <-4 msg words ->        <-  16 bytes  ->
     * +-+-+-+-+-+-+--+        +-+-+-+-+-+-+--+
     * |0|1|2|3|0|1|..|0-3     |0|0|0|0|0|0|..|
     * +-+-+-+-+-+-+ -|        +-+-+-+-+-+-+ -|
     * |0|1|2|3|0|1|  |4-7     |1|1| | | | |  |
     * +-+-+-+-+-+-+ -|  ====> +-+-+-+-+-+-+ -|
     * | | | | | | |  |        |2|2| | | | |  |
     * +-+-+-+-+-+-+ -|        +-+-+-+-+-+-+ -|
     * | | | | | | |  |        |3|3| | | | |  |
     * +-+-+-+-+-+-+--+        +-+-+-+-+-+-+--+
     *                          0 1 2 3 4 5  <-  word of msg
     *
     * (also swap byte order while slicing)
     */
    u32 msl[16] ALIGN(16);
    vu32 mv[4];
    vu32 m1, m2, m3, m4;
    for (unsigned i = 0; i < 16; i++) {
        *((u8 *)msl + i)      = *((u8 *)msg + i*4 + 0);
        *((u8 *)msl + i + 16) = *((u8 *)msg + i*4 + 1);
        *((u8 *)msl + i + 32) = *((u8 *)msg + i*4 + 2);
        *((u8 *)msl + i + 48) = *((u8 *)msg + i*4 + 3);
    }
    mv[3] = vec_ld( 0, msl); /* all first bytes */
    mv[2] = vec_ld(16, msl); /* all second bytes etc */
    mv[1] = vec_ld(32, msl);
    mv[0] = vec_ld(48, msl);

#define ror(l,v) vec_rl(v, vr ## l)

#define BLAKE2S_VG(M,N,a,b,c,d) \
    do { \
        (a) += (b) + (M);           \
        (d)  = ror(16, (d) ^ (a));  \
        (c) += (d);                 \
        (b)  = ror(12, (b) ^ (c));  \
        (a) += (b) + (N);           \
        (d)  = ror( 8, (d) ^ (a));  \
        (c) += (d);                 \
        (b)  = ror( 7, (b) ^ (c));  \
    } while (0)

    /* vec_sld(x,y,z):  shift concat(x,y) left by z bytes */
    /* vec_perm(v,w,p): pick bytes by index in p from concat(v,w) */
    /* vec_mergeh(x,y): pick x0 y0 x1 y1 from vectors (x0 x1 x2 x3) (y0..) */
#define FULLROUND(r) \
    do { \
        vu16 x1, x2, x3, x4; \
        /* Apply the round permutation sigma(r) to the byte vectors */ \
        vu8 sigma_even = blake2s_vsigma_even[r]; \
        vu8 sigma_odd  = blake2s_vsigma_odd[r]; \
        /* Assemble words 0-15 of the message */\
        x1 = (vu16)vec_perm(mv[0], mv[1], sigma_even); \
        x2 = (vu16)vec_perm(mv[2], mv[3], sigma_even); \
        x3 = (vu16)vec_perm(mv[0], mv[1], sigma_odd); \
        x4 = (vu16)vec_perm(mv[2], mv[3], sigma_odd); \
        m1 = (vu32)vec_mergeh(x1, x2); /* has  0,  2,  4,  6 */\
        m2 = (vu32)vec_mergeh(x3, x4); /* has  1,  3,  5,  7 */\
        m3 = (vu32)vec_mergel(x1, x2); /* has  8, 10, 12, 14 */\
        m4 = (vu32)vec_mergel(x3, x4); /* has  9, 11, 13, 15 */\
        \
        /* First half:  apply G() on rows */ \
        BLAKE2S_VG(m1,m2,va,vb,vc,vd); \
        \
        /* Second half: apply G() on diagonals */ \
        vb = vec_sld(vb, vb, 4); \
        vc = vec_sld(vc, vc, 8); \
        vd = vec_sld(vd, vd, 12); \
        BLAKE2S_VG(m3,m4,va,vb,vc,vd); \
        vb = vec_sld(vb, vb, 12); \
        vc = vec_sld(vc, vc, 8); \
        vd = vec_sld(vd, vd, 4); \
    } while (0)

    /* 10 rounds times 2 applications of G */
    FULLROUND(0);
    FULLROUND(1);
    FULLROUND(2);
    FULLROUND(3);
    FULLROUND(4);
    FULLROUND(5);
    FULLROUND(6);
    FULLROUND(7);
    FULLROUND(8);
    FULLROUND(9);

    H[0] ^= va;
    H[0] ^= vc;
    H[1] ^= vb;
    H[1] ^= vd;
}

void blake2s_compress(struct blake2s_ctx *ctx, const void *m)
{
    /* vec_ld: load from __16-byte_aligned_address__ */
    vu32 H[2];
    vu32 va, vb, vc, vd;
    vu32 vpr;
    va = H[0] = vec_ld( 0, ctx->H);
    vb = H[1] = vec_ld(16, ctx->H);
          vpr = vec_ld( 0, &ctx->t[0]); /* t[0], t[1], f[0], f[1] */
    vc = blake2s_viv[0];
    vd = blake2s_viv[1] ^ vpr;

    blake2s_10rounds(va,vb,vc,vd, H, m);

    /* vec_st: store vector at 16-byte aligned address */
    vec_st(H[0],  0, ctx->H);
    vec_st(H[1], 16, ctx->H);
}
