
#include "blake2s.h"
#include "blake2s-internal.h"

static inline u32 ror(unsigned l, u32 x) { return (x >> l) | (x << (32-l)); }

static inline void butil_le32_copy(void *dst, const void *src, unsigned bytes)
{
    u32 *udst = (void *)dst;
    const unsigned char *usrc = src;
    unsigned i = 0;
    for (; i < bytes/4; i++)
        udst[i] = read_le32(usrc + i*4);
}


static void blake2s_10rounds(u32 v[16], const u32 m[16])
{
#define BLAKE2S_G(M,N,a,b,c,d) \
    do { \
        (a) += (b) + (M);           \
        (d) = ror(16, (d) ^ (a));   \
        (c) += (d);                 \
        (b) = ror(12, (b) ^ (c));   \
        (a) += (b) + (N);           \
        (d) = ror( 8, (d) ^ (a));   \
        (c) += (d);                 \
        (b) = ror( 7, (b) ^ (c));   \
    } while (0)

#define Si(i,j) blake2s_sigma[(i)][(j)]

    /* 10 rounds times 8 applications of G */
    for (unsigned r = 0; r < 10; r++) {
        BLAKE2S_G(m[Si(r, 0)], m[Si(r, 1)], v[ 0], v[ 4], v[ 8], v[12]);
        BLAKE2S_G(m[Si(r, 2)], m[Si(r, 3)], v[ 1], v[ 5], v[ 9], v[13]);
        BLAKE2S_G(m[Si(r, 4)], m[Si(r, 5)], v[ 2], v[ 6], v[10], v[14]);
        BLAKE2S_G(m[Si(r, 6)], m[Si(r, 7)], v[ 3], v[ 7], v[11], v[15]);

        BLAKE2S_G(m[Si(r, 8)], m[Si(r, 9)], v[ 0], v[ 5], v[10], v[15]);
        BLAKE2S_G(m[Si(r,10)], m[Si(r,11)], v[ 1], v[ 6], v[11], v[12]);
        BLAKE2S_G(m[Si(r,12)], m[Si(r,13)], v[ 2], v[ 7], v[ 8], v[13]);
        BLAKE2S_G(m[Si(r,14)], m[Si(r,15)], v[ 3], v[ 4], v[ 9], v[14]);
    }
}

void blake2s_compress(struct blake2s_ctx *ctx, const void *msg)
{
    u32 v[16];
    u32 m[16];
    butil_le32_copy(m, msg, sizeof(m));
    butil_copy_words(v, ctx->H, sizeof(ctx->H));
    v[ 8] = blake2s_iv[0];
    v[ 9] = blake2s_iv[1];
    v[10] = blake2s_iv[2];
    v[11] = blake2s_iv[3];
    v[12] = blake2s_iv[4] ^ ctx->t[0];
    v[13] = blake2s_iv[5] ^ ctx->t[1];
    v[14] = blake2s_iv[6] ^ ctx->f[0];
    v[15] = blake2s_iv[7] ^ ctx->f[1];

    blake2s_10rounds(v, m);

    for (unsigned i = 0; i < 8;) {
        ctx->H[i] ^= v[i] ^ v[i+8]; i++;
        ctx->H[i] ^= v[i] ^ v[i+8]; i++;
        ctx->H[i] ^= v[i] ^ v[i+8]; i++;
        ctx->H[i] ^= v[i] ^ v[i+8]; i++;
    }
}
