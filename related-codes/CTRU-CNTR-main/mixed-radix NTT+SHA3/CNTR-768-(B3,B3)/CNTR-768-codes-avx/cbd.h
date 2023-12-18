#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "params.h"
#include <immintrin.h>
#include "poly.h"


void cbd2(poly * restrict r, const __m256i buf[2*CTRU_N/128]);
void cbd3(poly *r, const uint8_t buf[3*CTRU_N/4]);

#endif
