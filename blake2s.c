/*
 Written in 2013 by Ulrik Sverdrup

 To the extent possible under law, the author(s) have dedicated all copyright
 and related and neighboring rights to this software to the public domain
 worldwide. This software is distributed without any warranty.

 You should have received a copy of the CC0 Public Domain Dedication along with
 this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "blake2s.h"
#include "blake2s-internal.h"

/* BLAKE2s: designed for 32-bit and smaller arches
 * + Message is interpreted in little endian
 * + Padding just zerofills to block size
 * + block size is 64 bytes
 *
 * Parameter block (length, position)
 * Digest byte length (1, 0) in [1,32]
 * Key byte length (1, 1)    in [0,32]
 * Fanout         (1, 2)   = 1 for non-tree hashing style
 * Max depth      (1, 3)   = 1 for non-tree hashing style
 * Salt (8, 16-23) default zeros
 * Personalization (8, 24-32) default zeros
 */
#define B2S_BLOCK BLAKE2S_BLOCK
#define B2S_PARAM_KEY_IDX 1
#define B2S_PARAM_WORDS 4
#define B2S_SALT_WORDS  2
#define B2S_PERS_WORDS  2
/*Require 8 = B2S_PARAM_WORDS + B2S_SALT_WORDS + B2S_PERS_WORDS*/

static const u8  blake2s_salt_def [4*B2S_SALT_WORDS]  = {0};
static const u8  blake2s_pers_def [4*B2S_PERS_WORDS]  = {0};

/* Param word 1: diglen,keylen,1,1 */
#define LE32W(x,y,z,w) (u32)((x)|((y)<<8)|((z)<<16)|((w)<<24))
#define B2S_FIRST_PARAM(dlen,klen) LE32W(dlen,klen,1,1)

#define B2S_IO_CHUNKSIZ (8 << 10)

static void butil_copy_fast(void *dst, const void *src, unsigned bytes)
{
    u8 *udst = dst;
    const u8 *usrc = src;
    unsigned off = bytes - (bytes & 3);
    butil_copy_words(dst, src, bytes);
    switch (bytes & 3) {
        case 3: udst[off] = usrc[off]; off++;
        case 2: udst[off] = usrc[off]; off++;
        case 1: udst[off] = usrc[off]; off++;
    }
}

static void bstate_inc_t(struct blake2s_ctx *ctx, size_t inc)
{
    ctx->t[0] += inc;
    ctx->t[1] += (ctx->t[0] < inc);
}

static void bstate_set_final_block(struct blake2s_ctx *ctx)
{
    ctx->f[0] = ~0L;
}

static void bstate_buf_zeropad(struct blake2s_ctx *ctx)
{
    memset(ctx->buf + ctx->buf_len, 0, B2S_BLOCK - ctx->buf_len);
}

static void bstate_buf_add(struct blake2s_ctx *ctx, const void *src,
                          size_t len, size_t off)
{
    butil_copy_fast(ctx->buf + off, src, len);
    ctx->buf_len = off + len;
}

#define bstate_buf_append(ctx,s,l) bstate_buf_add(ctx,(s),l,(ctx)->buf_len)
#define bstate_buf_set(ctx,s,l) bstate_buf_add(ctx,(s),l,0)

void blake2s_update(struct blake2s_ctx *ctx, const void *src, size_t len)
{
    unsigned rest = B2S_BLOCK - ctx->buf_len;
    size_t src_off = 0;

    /* Always save one full block in slop buffer */
    if (ctx->buf_len + len <= B2S_BLOCK) {
        bstate_buf_append(ctx, src, len);
        return;
    }
    /* first block */
    bstate_buf_append(ctx, src, rest);
    src_off += rest;
    len -= rest;

    /* full blocks */
    while (1) {
        bstate_inc_t(ctx, B2S_BLOCK);
        blake2s_compress(ctx, ctx->buf);

        if (len <= B2S_BLOCK) break;

        butil_copy_words(ctx->buf, (char *)src + src_off, B2S_BLOCK);
        len -= B2S_BLOCK;
        src_off += B2S_BLOCK;
    }

    bstate_buf_set(ctx, (char *)src + src_off, len);
}

static void bstate_secure_zero(struct blake2s_ctx *ctx)
{
    size_t len = sizeof(*ctx);
    volatile u8 *ptr = (void *)ctx;
    while (len--) *ptr++ = 0;
}

static void bstate_output_digest(struct blake2s_ctx *ctx, unsigned char *out)
{
    /* write digest in le32 to `out` */
    unsigned i = 0, off = 0;
    for (; i < ctx->digest_len/4; i++)
        write_le32(out+i*4, ctx->H[i]);
    while (i*4 + off < ctx->digest_len) {
        u32 H = ctx->H[i];
        out[i*4 + off] = (H >> off*8) & 0xff;
        off++;
    }
}

void blake2s_final(struct blake2s_ctx *ctx, unsigned char *out)
{
    bstate_buf_zeropad(ctx);
    bstate_set_final_block(ctx);
    bstate_inc_t(ctx, ctx->buf_len);
    blake2s_compress(ctx, ctx->buf);
    bstate_output_digest(ctx, out);
    bstate_secure_zero(ctx);
}

static void blake2s_init_ex(struct blake2s_ctx *ctx, const void *salt,
                            unsigned dig_len, unsigned key_len)
{
    unsigned i = 0;
    ctx->H[i] = blake2s_iv[i] ^ B2S_FIRST_PARAM(dig_len,key_len); i++;
    for (; i < B2S_PARAM_WORDS; i++)
        ctx->H[i] = blake2s_iv[i]; /* Param words 1-3 are 0 in sequential mode*/
    for (unsigned j = 0; j < B2S_SALT_WORDS; j++, i++)
        ctx->H[i] = blake2s_iv[i] ^ read_le32((const u8 *)salt + j*4);
    for (unsigned j = 0; j < B2S_PERS_WORDS; j++, i++)
        ctx->H[i] = blake2s_iv[i] ^ read_le32((const u8 *)blake2s_pers_def+j*4);
    ctx->t[0] = 0;
    ctx->t[1] = 0;
    ctx->f[0] = 0;
    ctx->f[1] = 0;
    ctx->digest_len = dig_len;
    ctx->buf_len = 0;
}

int blake2s_init_salted(struct blake2s_ctx *ctx, const void *salt,
                        unsigned dig_len)
{
    if (!salt) salt = blake2s_salt_def;
    if (dig_len < 1 || dig_len > BLAKE2S_LEN) return -1;
    blake2s_init_ex(ctx, salt, dig_len, 0);
    return 0;
}

void blake2s_init(struct blake2s_ctx *ctx)
{
    blake2s_init_ex(ctx, blake2s_salt_def, BLAKE2S_LEN, 0);
}

int blake2s_init_keyed(struct blake2s_ctx *ctx, const void *salt,
                        const void *key, unsigned key_len, unsigned dig_len)
{
    u8 key_block[B2S_BLOCK] = {0};

    if (key_len < 1 || key_len > BLAKE2S_KEY_LEN)
        return -1;
    if (dig_len < 1 || dig_len > BLAKE2S_LEN)
        return -1;
    if (!salt) salt = blake2s_salt_def;

    blake2s_init_ex(ctx, salt, dig_len, key_len);

    memcpy(key_block, key, key_len);
    blake2s_update(ctx, key_block, B2S_BLOCK);
    memset(key_block, 0xff, sizeof(key_block));
    return 1;
}

void blake2s(unsigned char *out, const void *src, size_t len)
{
    struct blake2s_ctx ctx;
    blake2s_init(&ctx);
    blake2s_update(&ctx, src, len);
    blake2s_final(&ctx, out);
}

int blake2s_file(unsigned char *out, FILE *stream)
{
    struct blake2s_ctx ctx;
    unsigned char *buf;
    int ret = 1;

    if (!(buf = malloc(B2S_IO_CHUNKSIZ)))
        return -1;
    blake2s_init(&ctx);
    while (1) {
        size_t read = fread(buf, 1, B2S_IO_CHUNKSIZ, stream);
        if (!read && ferror(stream)) {
            ret = -1;
            goto _out;
        }
        if (!read)
            break;
        blake2s_update(&ctx, buf, read);
    }
    blake2s_final(&ctx, out);
_out:
    free(buf);
    return ret;
}


/* Self-test code */

static char *hexdigest(char *buf, const u8 *digest, size_t len)
{
    char *digits = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        buf[2*i]   = digits[digest[i]  >> 4];
        buf[2*i+1] = digits[digest[i] & 0xf];
    }
    buf[2*len] = 0;
    return buf;
}

static int test_checkdigest(const void *digest, const void *exp, int verbose)
{
    char hex[BLAKE2S_LEN*2+1];
    if (!memcmp(digest, exp, BLAKE2S_LEN)) {
        if (verbose)
            printf("PASS %s\n", hexdigest(hex, digest, BLAKE2S_LEN));
        return 1;
    }
    printf("FAIL. Got: %s\n", hexdigest(hex, digest, BLAKE2S_LEN));
    printf("FAIL. Exp: %s\n", hexdigest(hex, exp, BLAKE2S_LEN));
    return 0;
}

static int test_one_vec(const void *input, size_t len, const void *exp, int verbose)
{
    u8 digest[BLAKE2S_LEN];
    memset(digest, 0, BLAKE2S_LEN);
    blake2s(digest, input, len);
    return test_checkdigest(digest, exp, verbose);
}
static int test_keyed_vec(const void *input, size_t len, const void *exp,
                          const void *key, unsigned keylen, int verbose)
{
    u8 digest[BLAKE2S_LEN];
    struct blake2s_ctx ctx;
    memset(digest, 0, BLAKE2S_LEN);
    blake2s_init_keyed(&ctx, NULL, key, keylen, BLAKE2S_LEN);
    blake2s_update(&ctx, input, len);
    blake2s_final(&ctx, digest);
    return test_checkdigest(digest, exp, verbose);
}
#include "blake-kat.h"

static int test_vectors(void)
{
    int ret = 1;
    char input[KAT_LENGTH] = {0};
    unsigned char key[BLAKE2S_KEY_LEN];
    for (unsigned i = 0; i < sizeof(input); i++)
        input[i] = i;
    for (unsigned i = 0; i < sizeof(key); i++)
        key[i] = i;
    for (unsigned i = 0; i < KAT_LENGTH; i++) {
        if (!test_one_vec(input, i, blake2s_kat[i], 0))
            ret = 0;
    }
    for (unsigned i = 0; i < KAT_LENGTH; i++) {
        if (!test_keyed_vec(input, i, blake2s_keyed_kat[i], key, BLAKE2S_KEY_LEN, 0))
            ret = 0;
    }
    return ret;
}

int main(int bjorn, char *daehlie[])
{
    unsigned char buf[BLAKE2S_LEN];
    char hex[BLAKE2S_LEN*2+1];
    if (test_vectors()) printf("Self-test ok.\n");
    while (bjorn > 1) {
        FILE *f = fopen(daehlie[1], "r");
        if (!f) {
            perror("open file:");
            break;
        }
        if (blake2s_file(buf, f))
            printf("%s  %s\n", hexdigest(hex, buf, BLAKE2S_LEN), daehlie[1]);
        else
            perror("hashing file:");
        fclose(f);
        bjorn--; daehlie++;
    }
}
