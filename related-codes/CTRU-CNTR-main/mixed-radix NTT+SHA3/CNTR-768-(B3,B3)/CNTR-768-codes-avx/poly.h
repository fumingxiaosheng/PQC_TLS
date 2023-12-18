#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"
#include "align.h"


typedef ALIGNED_INT16(CTRU_N) poly;

void poly_freeze(poly *a);
void poly_crt(poly *h, const poly *h1, const poly *h2);
void poly_add(poly *c, const poly *a, const poly *b);
void poly_double(poly *b, const poly *a);
void poly_reduce7681(poly *a);
void poly_frommont(poly *a);
void poly_reduce(poly *a);
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
