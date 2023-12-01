#include <stdint.h>
#include "params.h"
#include "cbd.h"

static uint32_t load32_littleendian(const uint8_t x[4])
{
  uint32_t r;
  r = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  r |= (uint32_t)x[3] << 24;
  return r;
}

static uint64_t load_littleendian(const uint8_t *x, int bytes)
{
  int i;
  uint64_t r = x[0];
  for (i = 1; i < bytes; i++)
    r |= (uint64_t)x[i] << (8 * i);
  return r;
}

void cbd2(poly *r, const uint8_t buf[CTRU_COIN_BYTES / 2])
{
  unsigned int i, j;
  uint32_t t, d;
  int16_t a, b;

  for (i = 0; i < CTRU_N / 8; i++)
  {
    t = load32_littleendian(buf + 4 * i);
    d = t & 0x55555555;
    d += (t >> 1) & 0x55555555;

    for (j = 0; j < 8; j++)
    {
      a = (d >> (4 * j + 0)) & 0x3;
      b = (d >> (4 * j + 2)) & 0x3;
      r->coeffs[8 * i + j] = a - b;
    }
  }
}

void cbd3(poly *r, const uint8_t buf[CTRU_COIN_BYTES / 2])
{
  uint32_t t, d, a[4], b[4];
  int i, j;

  for (i = 0; i < CTRU_N / 4; i++)
  {
    t = load_littleendian(buf + 3 * i, 3);
    d = 0;
    for (j = 0; j < 3; j++)
      d += (t >> j) & 0x249249;

    a[0] = d & 0x7;
    b[0] = (d >> 3) & 0x7;
    a[1] = (d >> 6) & 0x7;
    b[1] = (d >> 9) & 0x7;
    a[2] = (d >> 12) & 0x7;
    b[2] = (d >> 15) & 0x7;
    a[3] = (d >> 18) & 0x7;
    b[3] = (d >> 21);

    r->coeffs[4 * i + 0] = (int16_t)(a[0] - b[0]);
    r->coeffs[4 * i + 1] = (int16_t)(a[1] - b[1]);
    r->coeffs[4 * i + 2] = (int16_t)(a[2] - b[2]);
    r->coeffs[4 * i + 3] = (int16_t)(a[3] - b[3]);
  }
}

void cbd4(poly *r, const uint8_t buf[CTRU_COIN_BYTES / 2])
{
  uint32_t t, d, a[4], b[4];
  int i, j;

  for (i = 0; i < CTRU_N / 4; i++)
  {
    t = load_littleendian(buf + 4 * i, 4);
    d = 0;
    for (j = 0; j < 4; j++)
      d += (t >> j) & 0x11111111;

    a[0] = d & 0xf;
    b[0] = (d >> 4) & 0xf;
    a[1] = (d >> 8) & 0xf;
    b[1] = (d >> 12) & 0xf;
    a[2] = (d >> 16) & 0xf;
    b[2] = (d >> 20) & 0xf;
    a[3] = (d >> 24) & 0xf;
    b[3] = (d >> 28);

    r->coeffs[4 * i + 0] = (uint16_t)(a[0] - b[0]);
    r->coeffs[4 * i + 1] = (uint16_t)(a[1] - b[1]);
    r->coeffs[4 * i + 2] = (uint16_t)(a[2] - b[2]);
    r->coeffs[4 * i + 3] = (uint16_t)(a[3] - b[3]);
  }
}

void cbd5(poly *r, const uint8_t buf[CTRU_COIN_BYTES / 2])
{
  uint64_t t, d, a[4], b[4];
  int i, j;

  for (i = 0; i < CTRU_N / 4; i++)
  {
    t = load_littleendian(buf + 5 * i, 5);
    d = 0;
    for (j = 0; j < 5; j++)
      d += (t >> j) & 0x0842108421UL;

    a[0] = d & 0x1f;
    b[0] = (d >> 5) & 0x1f;
    a[1] = (d >> 10) & 0x1f;
    b[1] = (d >> 15) & 0x1f;
    a[2] = (d >> 20) & 0x1f;
    b[2] = (d >> 25) & 0x1f;
    a[3] = (d >> 30) & 0x1f;
    b[3] = (d >> 35);

    r->coeffs[4 * i + 0] = (uint16_t)(a[0] - b[0]);
    r->coeffs[4 * i + 1] = (uint16_t)(a[1] - b[1]);
    r->coeffs[4 * i + 2] = (uint16_t)(a[2] - b[2]);
    r->coeffs[4 * i + 3] = (uint16_t)(a[3] - b[3]);
  }
}