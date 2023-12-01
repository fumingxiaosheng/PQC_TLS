#ifndef PACK_H
#define PACK_H

#include <stdint.h>
#include "poly.h"
#include "params.h"

void pack_pk(unsigned char *r, const poly *a);
void packpk_avx(unsigned char *r, const poly *a);
void unpack_pk(poly *r, const unsigned char *a);
void unpackpk_avx(poly *r, const unsigned char *a);
void pack_sk(unsigned char *r, const poly *a);
void packsk_avx(unsigned char *r, const poly *a);
void unpack_sk(poly *r, const unsigned char *a);
void unpacksk_avx(poly *r, const unsigned char *a);
void pack_ct(unsigned char *r, const poly *a);
void packct_avx(unsigned char *r, const poly *a);
void unpack_ct(poly *r, const unsigned char *a);
void unpackct_avx(poly *r, const unsigned char *a);

#endif