#ifndef NTT_H
#define NTT_H

#include <stdint.h>

extern int16_t zetas[CTRU_NTT_N / 2];
extern int16_t zetas_inv[CTRU_NTT_N / 2];
extern int16_t zetas_base[CTRU_NTT_N / 4];

void ntt_256(int16_t b[], const int16_t a[]);
void invntt_256(int16_t b[], const int16_t a[]);

void basemul(int16_t c[], const int16_t a[], const int16_t b[], const int16_t zeta);
int baseinv(int16_t b[], const int16_t a[], const int16_t zeta);

#endif
