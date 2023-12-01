#include <stdint.h>
#include "cpucycles.h"
#include "params.h"
#include "reduce.h"
#include "ntt.h"
#include "poly.h"
#include "coding.h"
#include "cbd.h"

void poly_reduce(poly *a)
{
  for (int i = 0; i < CTRU_N; ++i)
    a->coeffs[i] = barrett_reduce(a->coeffs[i]);
}

void poly_freeze(poly *a)
{
  poly_reduce(a);
  for (int i = 0; i < CTRU_N; ++i)
    a->coeffs[i] = fqcsubq(a->coeffs[i]);
}

void poly_add(poly *c, const poly *a, const poly *b)
{
  for (int i = 0; i < CTRU_N; ++i)
    c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

void poly_double(poly *b, const poly *a)
{
  for (int i = 0; i < CTRU_N; ++i)
    b->coeffs[i] = 2 * a->coeffs[i];
}

void poly_tomont(poly *a)
{
  const int16_t t = (MONT * MONT) % CTRU_Q;
  for (int i = 0; i < CTRU_N; ++i)
    a->coeffs[i] = fqmul(a->coeffs[i], t);
}

void poly_frommont(poly *a)
{
  for (int i = 0; i < CTRU_N; ++i)
    a->coeffs[i] = fqmul(a->coeffs[i], 1);
}

void poly_doublemont(poly *a)
{
  const int16_t t = (((MONT * MONT) % CTRU_Q) * MONT) % CTRU_Q;

  for (int i = 0; i < CTRU_N; ++i)
    a->coeffs[i] = fqmul(a->coeffs[i], t);
}

void poly_ntt(poly *b, const poly *a)
{
  ntt_256(b->coeffs, a->coeffs);
  ntt_256(b->coeffs + 256, a->coeffs + 256);
#if (CTRU_ALPHA == 3)
  ntt_256(b->coeffs + 512, a->coeffs + 512);
#elif (CTRU_ALPHA == 4)
  ntt_256(b->coeffs + 512, a->coeffs + 512);
  ntt_256(b->coeffs + 768, a->coeffs + 768);
#endif
}

void poly_invntt(poly *b, const poly *a)
{
  invntt_256(b->coeffs, a->coeffs);
  invntt_256(b->coeffs + 256, a->coeffs + 256);
#if (CTRU_ALPHA == 3)
  invntt_256(b->coeffs + 512, a->coeffs + 512);
#elif (CTRU_ALPHA == 4)
  invntt_256(b->coeffs + 512, a->coeffs + 512);
  invntt_256(b->coeffs + 768, a->coeffs + 768);
#endif
}

void poly_basemul(poly *c, const poly *a, const poly *b)
{
  int i;

  for (i = 0; i < CTRU_NTT_N / 4; ++i)
  {
    basemul(c->coeffs + 4 * CTRU_ALPHA * i,
            a->coeffs + 4 * CTRU_ALPHA * i,
            b->coeffs + 4 * CTRU_ALPHA * i,
            zetas[64 + i]);
    basemul(c->coeffs + 4 * CTRU_ALPHA * i + 2 * CTRU_ALPHA,
            a->coeffs + 4 * CTRU_ALPHA * i + 2 * CTRU_ALPHA,
            b->coeffs + 4 * CTRU_ALPHA * i + 2 * CTRU_ALPHA,
            -zetas[64 + i]);
  }
}

int poly_baseinv(poly *b, const poly *a)
{
  int i;
  int r = 0;
#if (CTRU_ALPHA == 2)
  for (i = 0; i < CTRU_NTT_N / 4; ++i)
  {
    r += baseinv(b->coeffs + 4 * CTRU_ALPHA * i,
                 a->coeffs + 4 * CTRU_ALPHA * i,
                 zetas[64 + i]);
    r += baseinv(b->coeffs + 4 * CTRU_ALPHA * i + 2 * CTRU_ALPHA,
                 a->coeffs + 4 * CTRU_ALPHA * i + 2 * CTRU_ALPHA,
                 -zetas[64 + i]);
  }
#elif ((CTRU_ALPHA == 3) || (CTRU_ALPHA == 4))
  for (i = 0; i < CTRU_NTT_N / 4; ++i)
  {
    r += baseinv(b->coeffs + 4 * CTRU_ALPHA * i,
                 a->coeffs + 4 * CTRU_ALPHA * i,
                 zetas_base[i]);
    r += baseinv(b->coeffs + 4 * CTRU_ALPHA * i + 2 * CTRU_ALPHA,
                 a->coeffs + 4 * CTRU_ALPHA * i + 2 * CTRU_ALPHA,
                 -zetas_base[i]);
  }
#endif
  return r;
}

void poly_sample(poly *a, const unsigned char buf[CTRU_COIN_BYTES / 2])
{
#if (CTRU_ALPHA == 2)
  cbd3(a, buf);
#elif (CTRU_ALPHA == 3)
  cbd3(a, buf);
#elif (CTRU_ALPHA == 4)
  cbd2(a, buf);
#endif
}

void poly_split(poly *b, const poly *a)
{
  int i;
  int16_t b0[CTRU_NTT_N], b1[CTRU_NTT_N];
#if (CTRU_ALPHA == 3)
  int16_t b2[CTRU_NTT_N];
#elif (CTRU_ALPHA == 4)
  int16_t b2[CTRU_NTT_N], b3[CTRU_NTT_N];
#endif

  for (i = 0; i < CTRU_NTT_N; i++)
  {
    b0[i] = a->coeffs[CTRU_ALPHA * i];
    b1[i] = a->coeffs[CTRU_ALPHA * i + 1];
#if (CTRU_ALPHA == 3)
    b2[i] = a->coeffs[CTRU_ALPHA * i + 2];
#elif (CTRU_ALPHA == 4)
    b2[i] = a->coeffs[CTRU_ALPHA * i + 2];
    b3[i] = a->coeffs[CTRU_ALPHA * i + 3];
#endif
  }

  for (i = 0; i < CTRU_NTT_N; i++)
  {
    b->coeffs[i] = b0[i];
    b->coeffs[CTRU_NTT_N + i] = b1[i];
#if (CTRU_ALPHA == 3)
    b->coeffs[2 * CTRU_NTT_N + i] = b2[i];
#elif (CTRU_ALPHA == 4)
    b->coeffs[2 * CTRU_NTT_N + i] = b2[i];
    b->coeffs[3 * CTRU_NTT_N + i] = b3[i];
#endif
  }
}

void poly_combine(poly *b, const poly *a)
{
  unsigned int i;
  int16_t b0[CTRU_NTT_N], b1[CTRU_NTT_N];
#if (CTRU_ALPHA == 3)
  int16_t b2[CTRU_NTT_N];
#elif (CTRU_ALPHA == 4)
  int16_t b2[CTRU_NTT_N], b3[CTRU_NTT_N];
#endif

  for (i = 0; i < CTRU_NTT_N; i++)
  {
    b0[i] = a->coeffs[i];
    b1[i] = a->coeffs[CTRU_NTT_N + i];
#if (CTRU_ALPHA == 3)
    b2[i] = a->coeffs[2 * CTRU_NTT_N + i];
#elif (CTRU_ALPHA == 4)
    b2[i] = a->coeffs[2 * CTRU_NTT_N + i];
    b3[i] = a->coeffs[3 * CTRU_NTT_N + i];
#endif
  }

  for (i = 0; i < CTRU_NTT_N; i++)
  {
    b->coeffs[CTRU_ALPHA * i] = b0[i];
    b->coeffs[CTRU_ALPHA * i + 1] = b1[i];
#if (CTRU_ALPHA == 3)
    b->coeffs[CTRU_ALPHA * i + 2] = b2[i];
#elif (CTRU_ALPHA == 4)
    b->coeffs[CTRU_ALPHA * i + 2] = b2[i];
    b->coeffs[CTRU_ALPHA * i + 3] = b3[i];
#endif
  }
}

#if (CTRU_Q2 != CTRU_Q)
#define N CTRU_N

static void poly_naivemul_q2(poly *c, const poly *a, const poly *b, const int Q)
{
  unsigned int i, j;
  int16_t r[2 * N] = {0};

  for (i = 0; i < N; i++)
    for (j = 0; j < N; j++)
    {
      r[i + j] += (int16_t)(a->coeffs[i] * b->coeffs[j]);
    }

  for (i = 3 * N / 2; i < 2 * N - 1; i++)
  {
    r[i - N / 2] = (r[i - N / 2] + r[i]);
    r[i - N] = (r[i - N] - r[i]);
  }
  for (i = N; i < 3 * N / 2; i++)
  {
    r[i - N / 2] = (r[i - N / 2] + r[i]);
    r[i - N] = (r[i - N] - r[i]);
  }

  for (i = 0; i < N; i++)
    c->coeffs[i] = r[i] & (Q - 1);
}
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
      t = (int32_t)((sigma->coeffs[8 * i + j] << CTRU_LOGQ2) + (CTRU_Q >> 1)) / CTRU_Q;
      t = t + (mask & (CTRU_Q2 >> 1));
      c->coeffs[8 * i + j] = t & (CTRU_Q2 - 1);
    }
  }
}

void poly_decode(unsigned char *msg,
                 const poly *c,
                 const poly *f)
{
  unsigned int i, j;
  poly mp;
  uint32_t tmp_mp[8];

  poly_naivemul_q2(&mp, c, f, CTRU_Q2);

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
