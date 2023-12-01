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

void cbd2(poly *r, const uint8_t buf[CTRU_N / 2])
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