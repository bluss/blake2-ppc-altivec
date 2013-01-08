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
static const vu32 vr8 = {24,24,24,24};
static const vu32 vr7 = {25,25,25,25};

static const vu8 blake2s_vsigma[10] =
{
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 },
};

static const vu32 blake2s_viv[2] = {
    { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a },
    { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 },
};

/* Zip together the even (odd) indices of two vectors */
static const vu8 zip_even =
{  0, 16,  2, 18,  4, 20,  6, 22,  8, 24, 10, 26, 12, 28, 14, 30};
static const vu8 zip_odd =
{  1, 17,  3, 19,  5, 21,  7, 23,  9, 25, 11, 27, 13, 29, 15, 31};

static void blake2s_10rounds(vu32 va, vu32 vb, vu32 vc, vu32 vd,
                             vu32 *vva, vu32 *vvb, const void *msg)
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
        *((u8 *)msl + i)      = *((u8 *)msg + i*4 + 3);
        *((u8 *)msl + i + 16) = *((u8 *)msg + i*4 + 2);
        *((u8 *)msl + i + 32) = *((u8 *)msg + i*4 + 1);
        *((u8 *)msl + i + 48) = *((u8 *)msg + i*4 + 0); 
    }
    mv[0] = vec_ld( 0, msl); /* all first bytes */
    mv[1] = vec_ld(16, msl); /* all second bytes etc */
    mv[2] = vec_ld(32, msl);
    mv[3] = vec_ld(48, msl);

#define ror(l,v) vec_rl(v, l)

#define BLAKE2S_VG(M,N,a,b,c,d) \
    do { \
        (a) += (b) + (M);           \
        (d) = ror(vr16, (d) ^ (a));  \
        (c) += (d);                 \
        (b) = ror(vr12, (b) ^ (c));  \
        (a) += (b) + (N);           \
        (d) = ror(vr8, (d) ^ (a));  \
        (c) += (d);                 \
        (b) = ror(vr7, (b) ^ (c));  \
    } while (0)

    /* vec_sld(x,y,z):  shift concat(x,y) left by z bytes */
    /* vec_perm(v,w,p): pick bytes by index in p from concat(v,w) */
    /* vec_mergeh(x,y): pick x0 y0 x1 y1 from vectors (x0 x1 x2 x3) (y0..) */
#define FULLROUND(r) \
    do { \
        vu16 x1, x2, x3, x4; \
        /* Apply the round permutation sigma(r,i) to the byte vectors */ \
        vu8 perm = blake2s_vsigma[r]; \
        m1 = vec_perm(mv[0],mv[0], perm); \
        m2 = vec_perm(mv[1],mv[1], perm); \
        m3 = vec_perm(mv[2],mv[2], perm); \
        m4 = vec_perm(mv[3],mv[3], perm); \
        /* Assemble words 0-15 of the message */\
        x1 = (vu16)vec_perm(m1, m2, zip_even); \
        x2 = (vu16)vec_perm(m3, m4, zip_even); \
        x3 = (vu16)vec_perm(m1, m2, zip_odd); \
        x4 = (vu16)vec_perm(m3, m4, zip_odd); \
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

    /* xor together v[i] and v[i+8] and store just the two first vectors */
    va ^= vc;
    vb ^= vd;
    *vva = va;
    *vvb = vb;
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

    blake2s_10rounds(va,vb,vc,vd, &va, &vb, m);

    H[0] ^= va;
    H[1] ^= vb;

    /* vec_st: store vector at 16-byte aligned address */
    vec_st(H[0],  0, ctx->H);
    vec_st(H[1], 16, ctx->H);
}
