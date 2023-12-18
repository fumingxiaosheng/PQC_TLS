#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"

typedef struct
{
  int16_t coeffs[CTRU_N];
} poly;

void poly_reduce(poly *a);
void poly_freeze(poly *a);

void poly_add(poly *c, const poly *a, const poly *b);
void poly_double(poly *b, const poly *a);

void poly_tomont(poly *a);
void poly_frommont(poly *a);

void poly_ntt(poly *b, const poly *a);
void poly_invntt(poly *b, const poly *a);
void poly_basemul(poly *c, const poly *a, const poly *b);
int poly_baseinv(poly *b, const poly *a);

void poly_sample(poly *a, const unsigned char *buf);

void poly_split(poly *b, const poly *a);
void poly_combine(poly *b, const poly *a);

void poly_encode_compress(poly *c, const poly *sigma, const unsigned char *m);
void poly_decode(unsigned char *m, const poly *c, const poly *fhat);
#endif
