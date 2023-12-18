#include "pack.h"

void pack_pk(unsigned char *r, const poly *a)
{
    packpk_avx(r,a);
}

void unpack_pk(poly *r, const unsigned char *a)
{
    unpackpk_avx(r,a);
}

void pack_sk(unsigned char *r, const poly *a)
{
     packsk_avx(r,a);
}

void unpack_sk(poly *r, const unsigned char *a)
{
    unpacksk_avx(r,a);
}

void pack_ct(unsigned char *r, const poly *a)
{
    packct_avx(r, a);
}

void unpack_ct(poly *r, const unsigned char *a)
{

    unpackct_avx(r,a);
}