#include <stdint.h>
#include <stdio.h>
#include "params.h"
#include "reduce.h"
#include "ntt.h"
#include "inverse.h"

int16_t zetas[CTRU_NTT_N / 2] = {
    2286, 2424, 1886, 1937, 1715, 2644, 2833, 2753, 16, 2500, 200, 137, 2946, 2260, 2255, 594,
    1024, 978, 2429, 1854, 3166, 2065, 1548, 3342, 729, 2418, 470, 2569, 3395, 2412, 2682, 2494,
    1278, 910, 2147, 1004, 1129, 2692, 2013, 2537, 3349, 410, 2107, 1668, 2826, 795, 755, 1295,
    2, 2041, 25, 3042, 1100, 2482, 3379, 3369, 3116, 2895, 923, 3346, 2585, 2030, 2928, 1176,
    2286, 2845, 919, 2721, 2409, 2186, 728, 3126, 878, 636, 604, 1036, 2377, 643, 328, 2852,
    126, 674, 1575, 1511, 160, 801, 2000, 1370, 2716, 2621, 2837, 3378, 376, 3438, 1243, 1491,
    1008, 1935, 2229, 1717, 1280, 2951, 2172, 589, 986, 226, 1954, 2825, 3008, 3305, 3030, 1557,
    110, 1631, 1375, 1374, 1731, 1687, 2624, 2074, 1987, 203, 2367, 809, 438, 1026, 2018, 2454};

int16_t zetas_inv[CTRU_NTT_N / 2] = {
    1003, 1439, 2431, 3019, 2648, 1090, 3254, 1470, 1383, 833, 1770, 1726, 2083, 2082, 1826, 3347,
    1900, 427, 152, 449, 632, 1503, 3231, 2471, 2868, 1285, 506, 2177, 1740, 1228, 1522, 2449,
    1966, 2214, 19, 3081, 79, 620, 836, 741, 2087, 1457, 2656, 3297, 1946, 1882, 2783, 3331,
    605, 3129, 2814, 1080, 2421, 2853, 2821, 2579, 331, 2729, 1271, 1048, 736, 2538, 612, 1171,
    2281, 529, 1427, 872, 111, 2534, 562, 341, 88, 78, 975, 2357, 415, 3432, 1416, 3455,
    2162, 2702, 2662, 631, 1789, 1350, 3047, 108, 920, 1444, 765, 2328, 2453, 1310, 2547, 2179,
    963, 775, 1045, 62, 888, 2987, 1039, 2728, 115, 1909, 1392, 291, 1603, 1028, 2479, 2433,
    2863, 1202, 1197, 511, 3320, 3257, 957, 3441, 704, 624, 813, 1742, 1520, 1571, 1792, 0};

int16_t zetas_base[CTRU_NTT_N / 4] = {
    55, 2544, 2416, 687, 2594, 2572, 1312, 1037, 2722, 1830, 2912, 2133, 219, 513, 1009, 1227,
    493, 113, 977, 3141, 1504, 3381, 1515, 2507, 640, 3204, 1086, 2023, 2843, 2587, 2696, 2953,
    487, 904, 902, 929, 1661, 2849, 1749, 2771, 1663, 1433, 1774, 2356, 2002, 3411, 826, 2882,
    1034, 812, 2554, 3236, 1752, 647, 1158, 2902, 10, 3291, 125, 1382, 2043, 2039, 3067, 3017};

void ntt_256(int16_t b[CTRU_NTT_N], const int16_t a[CTRU_NTT_N])
{
  unsigned int len, start, j, k;
  int16_t t, zeta;

  for (j = 0; j < 128; ++j)
  {
    t = fqmul(zetas[1], a[j + 128]);
    b[j + 128] = a[j] + a[j + 128] - t;
    b[j] = a[j] + t;
  }

  k = 2;
  for (len = 64; len >= 2; len >>= 1)
  {
    for (start = 0; start < 256; start = j + len)
    {
      zeta = zetas[k++];
      for (j = start; j < start + len; ++j)
      {
        t = fqmul(zeta, b[j + len]);
        b[j + len] = (b[j] - t);
        b[j] = (b[j] + t);
      }
    }
  }
}

void invntt_256(int16_t b[CTRU_NTT_N], const int16_t a[CTRU_NTT_N])
{
  unsigned int start, len, j, k;
  int16_t t, zeta;
  const int16_t n1 = (1U << 25) % CTRU_Q, n2 = (1U << 26) % CTRU_Q;

  for (j = 0; j < 256; ++j)
    b[j] = a[j];

  k = 0;

  len = 2;
  for (start = 0; start < 256; start = j + len)
  {
    zeta = zetas_inv[k++];
    for (j = start; j < start + len; ++j)
    {
      t = b[j];
      b[j] = (t + b[j + len]);
      b[j + len] = t - b[j + len];
      b[j + len] = fqmul(zeta, b[j + len]);
    }
  }

  len = 4;
  for (start = 0; start < 256; start = j + len)
  {
    zeta = zetas_inv[k++];
    for (j = start; j < start + len; ++j)
    {
      t = b[j];
      b[j] = (t + b[j + len]);
      b[j + len] = t - b[j + len];
      b[j + len] = fqmul(zeta, b[j + len]);
    }
  }

  len = 8;
  for (start = 0; start < 256; start = j + len)
  {
    zeta = zetas_inv[k++];
    for (j = start; j < start + len; ++j)
    {
      t = b[j];
      b[j] = barrett_reduce(t + b[j + len]);
      b[j + len] = t - b[j + len];
      b[j + len] = fqmul(zeta, b[j + len]);
    }
  }

  len = 16;
  for (start = 0; start < 256; start = j + len)
  {
    zeta = zetas_inv[k++];
    for (j = start; j < start + len; ++j)
    {
      t = b[j];
      b[j] = (t + b[j + len]);
      b[j + len] = t - b[j + len];
      b[j + len] = fqmul(zeta, b[j + len]);
    }
  }

  len = 32;
  for (start = 0; start < 256; start = j + len)
  {
    zeta = zetas_inv[k++];
    for (j = start; j < start + len; ++j)
    {
      t = b[j];
      b[j] = (t + b[j + len]);
      b[j + len] = t - b[j + len];
      b[j + len] = fqmul(zeta, b[j + len]);
    }
  }

  len = 64;
  for (start = 0; start < 256; start = j + len)
  {
    zeta = zetas_inv[k++];
    for (j = start; j < start + len; ++j)
    {
      t = b[j];
      b[j] = barrett_reduce(t + b[j + len]);
      b[j + len] = t - b[j + len];
      b[j + len] = fqmul(zeta, b[j + len]);
    }
  }

  for (j = 0; j < 128; ++j)
  {
    t = b[j] - b[j + 128];
    t = fqmul(zetas_inv[126], t);
    b[j] = b[j] + b[j + 128];
    b[j] = b[j] - t;
    b[j] = fqmul(n1, b[j]);
    b[j + 128] = fqmul(n2, t);
  }
}

#define CALC_D(a, b, x, y, d) (fqmul((a[x] + a[y]), (b[x] + b[y])) - d[x] - d[y])

#if (CTRU_ALPHA == 2)
void basemul(int16_t c[4], const int16_t a[4], const int16_t b[4], const int16_t zeta)
{
  int i;
  int16_t d[2 * CTRU_ALPHA];

  for (i = 0; i < 2 * CTRU_ALPHA; i++)
    d[i] = fqmul(a[i], b[i]);

  c[0] = d[0] + fqmul((CALC_D(a, b, 0, 3, d) + d[2]), zeta);
  c[1] = CALC_D(a, b, 0, 1, d) + fqmul(CALC_D(a, b, 2, 3, d), zeta);
  c[2] = barrett_reduce(CALC_D(a, b, 0, 2, d) + d[1] + fqmul(d[3], zeta));
  c[3] = barrett_reduce(CALC_D(a, b, 1, 2, d) + CALC_D(a, b, 1, 3, d));
}
#elif (CTRU_ALPHA == 3)
void basemul(int16_t c[6], const int16_t a[6], const int16_t b[6], const int16_t zeta)
{
  int i;
  int16_t d[2 * CTRU_ALPHA];

  for (i = 0; i < 2 * CTRU_ALPHA; i++)
    d[i] = fqmul(a[i], b[i]);

  c[0] = d[0] + fqmul((CALC_D(a, b, 1, 5, d) + CALC_D(a, b, 2, 4, d) + d[3]), zeta);
  c[1] = CALC_D(a, b, 0, 1, d) + fqmul((CALC_D(a, b, 2, 5, d) + CALC_D(a, b, 3, 4, d)), zeta);
  c[2] = barrett_reduce(CALC_D(a, b, 0, 2, d) + d[1] + fqmul((CALC_D(a, b, 3, 5, d) + d[4]), zeta));
  c[3] = barrett_reduce(CALC_D(a, b, 0, 3, d) + CALC_D(a, b, 1, 2, d) + fqmul(CALC_D(a, b, 4, 5, d), zeta));
  c[4] = barrett_reduce(CALC_D(a, b, 0, 4, d) + CALC_D(a, b, 1, 3, d) + d[2] + fqmul(d[5], zeta));
  c[5] = barrett_reduce(CALC_D(a, b, 0, 5, d) + CALC_D(a, b, 1, 4, d)) + CALC_D(a, b, 2, 3, d);
}
#elif (CTRU_ALPHA == 4)
void basemul(int16_t c[8], const int16_t a[8], const int16_t b[8], const int16_t zeta)
{
  int i;
  int16_t d[2 * CTRU_ALPHA];

  for (i = 0; i < 2 * CTRU_ALPHA; i++)
    d[i] = fqmul(a[i], b[i]);

  c[0] = d[0] + fqmul((CALC_D(a, b, 1, 6, d) + CALC_D(a, b, 2, 6, d) + CALC_D(a, b, 3, 5, d) + d[4]), zeta);
  c[1] = CALC_D(a, b, 0, 1, d) + fqmul((CALC_D(a, b, 2, 7, d) + CALC_D(a, b, 3, 6, d) + CALC_D(a, b, 4, 5, d)), zeta);
  c[2] = barrett_reduce(CALC_D(a, b, 0, 2, d) + d[1] + fqmul((CALC_D(a, b, 3, 7, d) + CALC_D(a, b, 4, 6, d) + d[5]), zeta));
  c[3] = barrett_reduce(CALC_D(a, b, 0, 3, d) + CALC_D(a, b, 1, 2, d) + fqmul((CALC_D(a, b, 4, 7, d) + CALC_D(a, b, 5, 6, d)), zeta));
  c[4] = barrett_reduce(CALC_D(a, b, 0, 4, d) + CALC_D(a, b, 1, 3, d) + d[2] + fqmul((CALC_D(a, b, 5, 7, d) + d[6]), zeta));
  c[5] = barrett_reduce(CALC_D(a, b, 0, 5, d) + CALC_D(a, b, 1, 5, d) + CALC_D(a, b, 2, 3, d)) + fqmul(CALC_D(a, b, 6, 7, d), zeta);
  c[6] = barrett_reduce(CALC_D(a, b, 0, 6, d) + CALC_D(a, b, 1, 4, d) + CALC_D(a, b, 2, 4, d)) + d[3] + fqmul(d[7], zeta);
  c[7] = barrett_reduce(CALC_D(a, b, 0, 7, d) + CALC_D(a, b, 1, 7, d)) + barrett_reduce(CALC_D(a, b, 2, 5, d) + CALC_D(a, b, 3, 4, d));
}
#endif

#if (CTRU_ALPHA == 2)
int baseinv(int16_t b[CTRU_MATRIX_N], const int16_t a[CTRU_MATRIX_N], const int16_t zeta)
{
  int16_t det, t[6];
  int r;

  t[0] = fqmul(a[1], a[3]);
  t[0] = fqmul(t[0], -zeta);
  t[0] += fqmul(a[0], a[0]);

  t[1] = fqmul(a[1], a[1]);
  t[1] -= fqmul(a[0], a[2]);

  t[2] = fqmul(a[2], a[2]);
  t[2] -= fqmul(a[1], a[3]);

  t[3] = fqmul(a[2], a[3]);
  t[3] = fqmul(t[3], -zeta);
  t[3] += fqmul(a[0], a[1]);

  t[4] = fqmul(a[3], a[3]);
  t[4] = fqmul(t[4], -zeta);
  t[4] += fqmul(a[0], a[2]);

  t[5] = fqmul(a[1], a[2]);
  t[5] -= fqmul(a[0], a[3]);

  b[0] = fqmul(a[2], t[1]);
  b[0] -= fqmul(a[3], t[3]);
  b[0] = fqmul(b[0], zeta);
  b[0] += fqmul(a[0], t[0]);

  b[1] = fqmul(a[3], t[4]);
  b[1] -= fqmul(a[2], t[5]);
  b[1] = fqmul(b[1], zeta);
  b[1] -= fqmul(a[1], t[0]);

  b[2] = fqmul(a[2], t[2]);
  b[2] = fqmul(b[2], zeta);
  b[2] += fqmul(a[1], t[3]);
  b[2] -= fqmul(a[0], t[4]);

  b[3] = fqmul(a[3], t[2]);
  b[3] = fqmul(b[3], -zeta);
  b[3] += fqmul(a[0], t[5]);
  b[3] -= fqmul(a[1], t[1]);

  det = fqmul(a[1], b[3]);
  det += fqmul(a[2], b[2]);
  det += fqmul(a[3], b[1]);
  det = fqmul(det, zeta);
  det += fqmul(a[0], b[0]);

  det = fqinv(det);
  det = fqmul(det, 2775);

  b[0] = fqmul(b[0], det);
  b[1] = fqmul(b[1], det);
  b[2] = fqmul(b[2], det);
  b[3] = fqmul(b[3], det);

  r = (uint16_t)det;
  r = (uint32_t)(-r) >> 31;
  return r - 1;
}
#elif ((CTRU_ALPHA == 3) || (CTRU_ALPHA == 4))
int baseinv(int16_t b[CTRU_MATRIX_N], const int16_t a[CTRU_MATRIX_N], const int16_t zeta)
{
  return rq_inverse(b, a, zeta);
}
#endif
