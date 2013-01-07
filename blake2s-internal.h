#ifndef BLAKE2S_INTERNAL_H_
#define BLAKE2S_INTERNAL_H_

typedef uint8_t  u8;
typedef uint32_t u32;

static const u32 blake2s_iv[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

static const u8 blake2s_sigma[10][16] =
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

void blake2s_compress(struct blake2s_ctx *ctx, const void *m);


static inline u32 to_le32(u32 x) {
    const int _one = 1;
    if (1 == *(unsigned char *)&_one) return x;
    return ((x>>24) | (x<<24) | ((x>>8) & 0xff00) | ((x<<8) & 0xff0000));
}
static inline u32 read_le32(const unsigned char *x) {
    return to_le32(*(u32 *)x);
}
static inline void write_le32(unsigned char *y, u32 x) {
    *y++ = x & 0xff;
    *y++ = (x >>  8) & 0xff;
    *y++ = (x >> 16) & 0xff;
    *y++ = (x >> 24) & 0xff;
}

static inline void butil_copy_words(void *dst, const void *src, unsigned bytes)
{
    u32 *udst = dst;
    const u32 *usrc = src;
    unsigned i = 0;
    for (; i < bytes/4; i++)
        udst[i] = usrc[i];
}


#endif /* BLAKE2S_INTERNAL_H_ */

