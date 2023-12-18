#include <stdint.h>
#include "cpucycles.h"
#include "params.h"
#include "ntt.h"
#include "poly.h"
#include "coding.h"
#include "cbd.h"
#include "consts.h"

void poly_freeze(poly *a)
{
  freeze_avx(a->coeffs);
}

void poly_add(poly *c, const poly *a, const poly *b)
{
  polyadd_avx(c->coeffs,a->coeffs,b->coeffs);
}

void poly_double(poly *b, const poly *a)
{
  polydouble_avx(b->coeffs, a->coeffs);
}


void poly_frommont(poly *a)
{
  frommont_avx(a->coeffs);
}


void poly_ntt7681(poly *b, const poly *a)
{
  ntt_avx7681(b->coeffs, a->coeffs);
}
void poly_invntt7681(poly *b, const poly *a)
{
  invntt_avx7681(b->coeffs, a->coeffs);
}

void poly_ntt(poly *b, const poly *a)
{
  ntt_avx(b, a);
}

void poly_invntt(poly *b, const poly *a)
{
   invntt_avx(b->coeffs, a->coeffs);
}

void poly_basemul(poly *c, const poly *a, const poly *b)
{
  basemul_avx(c, a, b);
}
void poly_basemul7681(poly *c, const poly *a, const poly *b)
{
  basemul_avx7681(c, a, b);
}
static int16_t fqred16(int16_t a) {
  int16_t t;

  t = a & 0x1FFF;
  a >>= 13;
  t += (a << 9) - a;
  return t;
}
void poly_reduce7681(poly *a) {
  unsigned int i;
  for(i = 0; i < CTRU_N; ++i)
    a->coeffs[i] = fqred16(a->coeffs[i]);
}
int poly_baseinv(poly *b, const poly *a)
{
  int r = 0;
  r = baseinv_avx(b->coeffs, a->coeffs);
  return r;
}


void poly_sample(poly *a, const unsigned char buf[4*CTRU_N/8])
{
  cbd2(a, buf);
}

void poly_split(poly *b, const poly *a)
{
  int i;
  int16_t b0[CTRU_NTT_N], b1[CTRU_NTT_N];
  int16_t b2[CTRU_NTT_N];

  for (i = 0; i < CTRU_NTT_N; i++)
  {
    b0[i] = a->coeffs[CTRU_ALPHA * i];
    b1[i] = a->coeffs[CTRU_ALPHA * i + 1];
    b2[i] = a->coeffs[CTRU_ALPHA * i + 2];
  }

  for (i = 0; i < CTRU_NTT_N; i++)
  {
    b->coeffs[i] = b0[i];
    b->coeffs[CTRU_NTT_N + i] = b1[i];
    b->coeffs[2 * CTRU_NTT_N + i] = b2[i];
  }
}

void poly_combine(poly *b, const poly *a)
{
  unsigned int i;
  int16_t b0[CTRU_NTT_N], b1[CTRU_NTT_N];
  int16_t b2[CTRU_NTT_N];

  for (i = 0; i < CTRU_NTT_N; i++)
  {
    b0[i] = a->coeffs[i];
    b1[i] = a->coeffs[CTRU_NTT_N + i];
    b2[i] = a->coeffs[2 * CTRU_NTT_N + i];
  }

  for (i = 0; i < CTRU_NTT_N; i++)
  {
    b->coeffs[CTRU_ALPHA * i] = b0[i];
    b->coeffs[CTRU_ALPHA * i + 1] = b1[i];
    b->coeffs[CTRU_ALPHA * i + 2] = b2[i];
  }
}

#if (CTRU_Q2 != CTRU_Q)
#define N CTRU_N

#endif
void poly_encode_compress(poly *c,
                          const poly *sigma,
                          const unsigned char *msg)
{
  unsigned int i, j;
  int16_t mask;
  uint8_t mh[CTRU_N / 8];
  uint8_t tmp;
  int16_t t;

  for (i = 0; i < CTRU_MSGBYTES; i++)
  {
    tmp = msg[i] & 0xF;
    mh[2 * i] = encode_e8(tmp);

    tmp = (msg[i] >> 4) & 0xF;
    mh[2 * i + 1] = encode_e8(tmp);
  }

  for (i = 0; i < CTRU_N / 8; i++)
  {
    for (j = 0; j < 8; j++)
    {
      mask = -(int16_t)((mh[i] >> j) & 1);
      t = ((((int32_t)sigma->coeffs[8 * i + j] + (mask & ((CTRU_Q + 1) >> 1))) << CTRU_LOGQ2) + (CTRU_Q >> 1)) / CTRU_Q;
      c->coeffs[8 * i + j] = t & (CTRU_Q2 - 1);
    }
  }
}


static int16_t poly_mulmod(int16_t a, int16_t b_pinv, int16_t b, int16_t p)
{
  int16_t t, u;
  t = (a * b_pinv) & 65535;
  u = (a * b) >> 16;
  t = (t * p) >> 16;
  t = (u - t) & 65535;
  return t;
}

static inline __m256i poly_mulmod_avx(const __m256i a, const __m256i b_pinv, const __m256i b, const __m256i p)
{
  __m256i t, u;
  t = _mm256_mullo_epi16(a, b_pinv);
  u = _mm256_mulhi_epi16(a, b);
  t = _mm256_mulhi_epi16(t, p);
  t = _mm256_sub_epi16(u, t);
  return t;
}

void poly_reduce(poly *a)
{
  barret_avx(a->coeffs);
}

void poly_crt_avx(poly *r, const poly *a, const poly *b)
{
  unsigned int i;
  __m256i u1, u2;
  const __m256i m_pinv = _mm256_set1_epi16(M2_MONT2_Q2INV);
  const __m256i m = _mm256_set1_epi16(M2_MONT2);
  const __m256i CTRU_QPRIME = _mm256_set1_epi16(7681);
  const __m256i q2 = _mm256_set1_epi16(3457);
  const __m256i mod = _mm256_set1_epi16(1023);

  for (i = 0; i < CTRU_N / 16; i++)
  {
    u1 = _mm256_load_si256((__m256i *)&a->coeffs[16 * i]);
    u2 = _mm256_load_si256((__m256i *)&b->coeffs[16 * i]);
    u2 = _mm256_sub_epi16(u2, u1);
    u2 = poly_mulmod_avx(u2, m_pinv, m, q2);
    u2 = _mm256_mullo_epi16(u2, CTRU_QPRIME);
    u1 = _mm256_add_epi16(u1, u2);
    u1 = _mm256_and_si256(u1, mod);
    _mm256_store_si256((__m256i *)&r->coeffs[16 * i], u1);
  }
}

void poly_crt(poly *h, const poly *h1, const poly *h2)
{
  int i = 0;
  int16_t u1, u2;
  for (i = 0; i < CTRU_N; i++)
  {
    u1 = h1->coeffs[i];
    u2 = h2->coeffs[i];
    u2 = u2 - u1;
    u2 = poly_mulmod(u2, M2_MONT2_Q2INV, M2_MONT2, 3457); //计算CRT_u*u2*R^(-1)
    u2 = (u2 * 7681) & 65535;
    u1 = u1 + u2;
    u1 = u1 & (1023);

    h->coeffs[i] = u1;
  }
}

void poly_decode(unsigned char *msg,
                 const poly *c,
                 const poly *f)
{
  unsigned int i, j;
  poly mp;
  uint32_t tmp_mp[8];
  poly chat1, chat2, fhat1, fhat2, mphat1, mphat2;
  poly_ntt7681(&chat1, c);
  poly_ntt7681(&fhat1, f);
  poly_basemul7681(&mphat1, &chat1, &fhat1);
  poly_reduce7681(&mphat1);
  poly_invntt7681(&mphat1,&mphat1);
  poly_ntt(&chat2, c);
  poly_ntt(&fhat2, f);
  poly_basemul(&mphat2, &chat2, &fhat2);
  poly_reduce(&mphat2);
  poly_invntt(&mphat2,&mphat2);
  poly_crt_avx(&mp,&mphat1,&mphat2);

  for (i = 0; i < CTRU_MSGBYTES; i++)
  {
    msg[i] = 0;
  }

  for (i = 0; i < CTRU_N / 8; i++)
  {
    for (j = 0; j < 8; j++)
    {
      tmp_mp[j] = (uint32_t)mp.coeffs[8 * i + j];
    }
    msg[i >> 1] |= decode_e8(tmp_mp) << ((i & 1) << 2);
  }
}
