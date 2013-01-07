/*
 Written in 2013 by Ulrik Sverdrup

 To the extent possible under law, the author(s) have dedicated all copyright
 and related and neighboring rights to this software to the public domain
 worldwide. This software is distributed without any warranty.

 You should have received a copy of the CC0 Public Domain Dedication along with
 this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#ifndef BLAKE2S_H_
#define BLAKE2S_H_

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define BLAKE2S_LEN 32      /* digest length */
#define BLAKE2S_KEY_LEN 32  /* max key length */
#define BLAKE2S_SALT_LEN 8  /* salt length */
#define BLAKE2S_BLOCK 64

struct blake2s_ctx;

/* blake2s_init_keyed: initialize BLAKE2s with key
 *
 * `salt`    must be NULL or BLAKE2S_SALT_LEN bytes
 * `key_len` must be 1 to BLAKE2S_KEY_LEN
 * `dig_len` must be 1 to BLAKE2S_LEN
 * 
 * returns < 0 on parameter error
 */
 int blake2s_init_keyed(struct blake2s_ctx *ctx, const void *salt,
                        const void *key, unsigned key_len, unsigned dig_len);
/* blake2s_init_salted: like blake2s_init_keyed
 * returns < 0 on parameter error
 */
 int blake2s_init_salted(struct blake2s_ctx *ctx, const void *salt,
                         unsigned dig_len);
void blake2s_init(struct blake2s_ctx *ctx);

void blake2s_update(struct blake2s_ctx *ctx, const void *src, size_t len);
void blake2s_final(struct blake2s_ctx *ctx, unsigned char *out);

void blake2s(unsigned char *out, const void *src, size_t len);
 int blake2s_file(unsigned char *out, FILE *stream);


#ifdef __GNUC__
#define ALIGN(x) __attribute__((aligned(x)))
#else
#define ALIGN(x)
#endif

struct blake2s_ctx {
    uint32_t H[8]; /* 16-aligned */
    unsigned char buf[BLAKE2S_BLOCK];
    uint32_t t[2]; /* 16-aligned */
    uint32_t f[2];
    unsigned buf_len;
    unsigned digest_len;
} ALIGN(16);

#endif /* BLAKE2S_H_ */

