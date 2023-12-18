#include "pack.h"

void pack_pk(unsigned char *r, const poly *a)
{
    unsigned int i;
    for (i = 0; i < CTRU_N / 2; i++)
    {
        r[3 * i + 0] = (a->coeffs[2 * i] >> 0);
        r[3 * i + 1] = (a->coeffs[2 * i] >> 8) | (a->coeffs[2 * i + 1] << 4);
        r[3 * i + 2] = (a->coeffs[2 * i + 1] >> 4);
    }
}

void unpack_pk(poly *r, const unsigned char *a)
{
    unsigned int i;
    for (i = 0; i < CTRU_N / 2; i++)
    {
        r->coeffs[2 * i] = ((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF;
        r->coeffs[2 * i + 1] = ((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF;
    }
}

void pack_sk(unsigned char *r, const poly *a)
{
    unsigned int i;
    uint8_t t[8];

    for (i = 0; i < CTRU_N / 8; i++)
    {
        t[0] = CTRU_BOUND - a->coeffs[8 * i + 0];
        t[1] = CTRU_BOUND - a->coeffs[8 * i + 1];
        t[2] = CTRU_BOUND - a->coeffs[8 * i + 2];
        t[3] = CTRU_BOUND - a->coeffs[8 * i + 3];
        t[4] = CTRU_BOUND - a->coeffs[8 * i + 4];
        t[5] = CTRU_BOUND - a->coeffs[8 * i + 5];
        t[6] = CTRU_BOUND - a->coeffs[8 * i + 6];
        t[7] = CTRU_BOUND - a->coeffs[8 * i + 7];

        r[4 * i + 0] = (t[0] >> 0) | (t[1] << 4);
        r[4 * i + 1] = (t[2] >> 0) | (t[3] << 4);
        r[4 * i + 2] = (t[4] >> 0) | (t[5] << 4);
        r[4 * i + 3] = (t[6] << 0) | (t[7] << 4);
    }
}

void unpack_sk(poly *r, const unsigned char *a)
{
    unsigned int i;

    for (i = 0; i < CTRU_N / 8; ++i)
    {
        r->coeffs[8 * i + 0] = (a[4 * i + 0] >> 0) & 15;
        r->coeffs[8 * i + 1] = (a[4 * i + 0] >> 4) & 15;
        r->coeffs[8 * i + 2] = (a[4 * i + 1] >> 0) & 15;
        r->coeffs[8 * i + 3] = (a[4 * i + 1] >> 4) & 15;
        r->coeffs[8 * i + 4] = (a[4 * i + 2] >> 0) & 15;
        r->coeffs[8 * i + 5] = (a[4 * i + 2] >> 4) & 15;
        r->coeffs[8 * i + 6] = (a[4 * i + 3] >> 0) & 15;
        r->coeffs[8 * i + 7] = (a[4 * i + 3] >> 4) & 15;

        r->coeffs[8 * i + 0] = CTRU_BOUND - r->coeffs[8 * i + 0];
        r->coeffs[8 * i + 1] = CTRU_BOUND - r->coeffs[8 * i + 1];
        r->coeffs[8 * i + 2] = CTRU_BOUND - r->coeffs[8 * i + 2];
        r->coeffs[8 * i + 3] = CTRU_BOUND - r->coeffs[8 * i + 3];
        r->coeffs[8 * i + 4] = CTRU_BOUND - r->coeffs[8 * i + 4];
        r->coeffs[8 * i + 5] = CTRU_BOUND - r->coeffs[8 * i + 5];
        r->coeffs[8 * i + 6] = CTRU_BOUND - r->coeffs[8 * i + 6];
        r->coeffs[8 * i + 7] = CTRU_BOUND - r->coeffs[8 * i + 7];
    }
}

void pack_ct(unsigned char *r, const poly *a)
{
    unsigned int i;
#if (CTRU_Q2 == 512)
    for (i = 0; i < CTRU_N / 8; ++i)
    {
        r[9 * i + 0] = a->coeffs[8 * i + 0] >> 0;
        r[9 * i + 1] = a->coeffs[8 * i + 0] >> 8 | ((int16_t)a->coeffs[8 * i + 1] << 1);
        r[9 * i + 2] = a->coeffs[8 * i + 1] >> 7 | ((int16_t)a->coeffs[8 * i + 2] << 2);
        r[9 * i + 3] = a->coeffs[8 * i + 2] >> 6 | ((int16_t)a->coeffs[8 * i + 3] << 3);
        r[9 * i + 4] = a->coeffs[8 * i + 3] >> 5 | ((int16_t)a->coeffs[8 * i + 4] << 4);
        r[9 * i + 5] = a->coeffs[8 * i + 4] >> 4 | ((int16_t)a->coeffs[8 * i + 5] << 5);
        r[9 * i + 6] = a->coeffs[8 * i + 5] >> 3 | ((int16_t)a->coeffs[8 * i + 6] << 6);
        r[9 * i + 7] = a->coeffs[8 * i + 6] >> 2 | ((int16_t)a->coeffs[8 * i + 7] << 7);
        r[9 * i + 8] = a->coeffs[8 * i + 7] >> 1;
    }
#elif (CTRU_Q2 == 1024)
    for (i = 0; i < CTRU_N / 4; ++i)
    {
        r[5 * i + 0] = (a->coeffs[4 * i + 0] >> 0);
        r[5 * i + 1] = (a->coeffs[4 * i + 0] >> 8) | ((int16_t)a->coeffs[4 * i + 1] << 2);
        r[5 * i + 2] = (a->coeffs[4 * i + 1] >> 6) | ((int16_t)a->coeffs[4 * i + 2] << 4);
        r[5 * i + 3] = (a->coeffs[4 * i + 2] >> 4) | ((int16_t)a->coeffs[4 * i + 3] << 6);
        r[5 * i + 4] = (a->coeffs[4 * i + 3] >> 2);
    }
#elif (CTRU_Q2 == 2048)
    for (i = 0; i < CTRU_N / 8; ++i)
    {
        r[11 * i + 0] = a->coeffs[8 * i + 0] >> 0;
        r[11 * i + 1] = a->coeffs[8 * i + 0] >> 8 | ((int16_t)a->coeffs[8 * i + 1] << 3);
        r[11 * i + 2] = a->coeffs[8 * i + 1] >> 5 | ((int16_t)a->coeffs[8 * i + 2] << 6);
        r[11 * i + 3] = a->coeffs[8 * i + 2] >> 2;
        r[11 * i + 4] = a->coeffs[8 * i + 2] >> 10 | ((int16_t)a->coeffs[8 * i + 3] << 1);
        r[11 * i + 5] = a->coeffs[8 * i + 3] >> 7 | ((int16_t)a->coeffs[8 * i + 4] << 4);
        r[11 * i + 6] = a->coeffs[8 * i + 4] >> 4 | ((int16_t)a->coeffs[8 * i + 5] << 7);
        r[11 * i + 7] = a->coeffs[8 * i + 5] >> 1;
        r[11 * i + 8] = a->coeffs[8 * i + 5] >> 9 | ((int16_t)a->coeffs[8 * i + 6] << 2);
        r[11 * i + 9] = a->coeffs[8 * i + 6] >> 6 | ((int16_t)a->coeffs[8 * i + 7] << 5);
        r[11 * i + 10] = a->coeffs[8 * i + 7] >> 3;
    }
#elif (CTRU_Q2 == 3457)
    for (i = 0; i < CTRU_N / 2; i++)
    {
        r[3 * i + 0] = (a->coeffs[2 * i] >> 0);
        r[3 * i + 1] = (a->coeffs[2 * i] >> 8) | (a->coeffs[2 * i + 1] << 4);
        r[3 * i + 2] = (a->coeffs[2 * i + 1] >> 4);
    }
#endif
}

void unpack_ct(poly *r, const unsigned char *a)
{
    unsigned int i;
#if (CTRU_Q2 == 512)
    for (i = 0; i < CTRU_N / 8; ++i)
    {
        r->coeffs[8 * i + 0] = ((a[9 * i + 0] >> 0) | ((uint16_t)a[9 * i + 1] << 8)) & 0x1FF;
        r->coeffs[8 * i + 1] = ((a[9 * i + 1] >> 1) | ((uint16_t)a[9 * i + 2] << 7)) & 0x1FF;
        r->coeffs[8 * i + 2] = ((a[9 * i + 2] >> 2) | ((uint16_t)a[9 * i + 3] << 6)) & 0x1FF;
        r->coeffs[8 * i + 3] = ((a[9 * i + 3] >> 3) | ((uint16_t)a[9 * i + 4] << 5)) & 0x1FF;
        r->coeffs[8 * i + 4] = ((a[9 * i + 4] >> 4) | ((uint16_t)a[9 * i + 5] << 4)) & 0x1FF;
        r->coeffs[8 * i + 5] = ((a[9 * i + 5] >> 5) | ((uint16_t)a[9 * i + 6] << 3)) & 0x1FF;
        r->coeffs[8 * i + 6] = ((a[9 * i + 6] >> 6) | ((uint16_t)a[9 * i + 7] << 2)) & 0x1FF;
        r->coeffs[8 * i + 7] = ((a[9 * i + 7] >> 7) | ((uint16_t)a[9 * i + 8] << 1)) & 0x1FF;
    }
#elif (CTRU_Q2 == 1024)
    for (i = 0; i < CTRU_N / 4; ++i)
    {
        r->coeffs[4 * i + 0] = ((a[5 * i + 0] >> 0) | ((uint16_t)a[5 * i + 1] << 8)) & 0x3FF;
        r->coeffs[4 * i + 1] = ((a[5 * i + 1] >> 2) | ((uint16_t)a[5 * i + 2] << 6)) & 0x3FF;
        r->coeffs[4 * i + 2] = ((a[5 * i + 2] >> 4) | ((uint16_t)a[5 * i + 3] << 4)) & 0x3FF;
        r->coeffs[4 * i + 3] = ((a[5 * i + 3] >> 6) | ((uint16_t)a[5 * i + 4] << 2)) & 0x3FF;
    }
#elif (CTRU_Q2 == 2048)
    for (i = 0; i < CTRU_N / 8; ++i)
    {
        r->coeffs[8 * i + 0] = ((a[11 * i + 0] >> 0) | ((uint16_t)a[11 * i + 1] << 8)) & 0x7FF;
        r->coeffs[8 * i + 1] = ((a[11 * i + 1] >> 3) | ((uint16_t)a[11 * i + 2] << 5)) & 0x7FF;
        r->coeffs[8 * i + 2] = ((a[11 * i + 2] >> 6) | ((uint16_t)a[11 * i + 3] << 2) | ((uint16_t)a[11 * i + 4] << 10)) & 0x7FF;
        r->coeffs[8 * i + 3] = ((a[11 * i + 4] >> 1) | ((uint16_t)a[11 * i + 5] << 7)) & 0x7FF;
        r->coeffs[8 * i + 4] = ((a[11 * i + 5] >> 4) | ((uint16_t)a[11 * i + 6] << 4)) & 0x7FF;
        r->coeffs[8 * i + 5] = ((a[11 * i + 6] >> 7) | ((uint16_t)a[11 * i + 7] << 1) | ((uint16_t)a[11 * i + 8] << 9)) & 0x7FF;
        r->coeffs[8 * i + 6] = ((a[11 * i + 8] >> 2) | ((uint16_t)a[11 * i + 9] << 6)) & 0x7FF;
        r->coeffs[8 * i + 7] = ((a[11 * i + 9] >> 5) | ((uint16_t)a[11 * i + 10] << 3)) & 0x7FF;
    }
#elif (CTRU_Q2 == 3457)
    for (i = 0; i < CTRU_N / 2; i++)
    {
        r->coeffs[2 * i] = ((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF;
        r->coeffs[2 * i + 1] = ((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF;
    }
#endif
}