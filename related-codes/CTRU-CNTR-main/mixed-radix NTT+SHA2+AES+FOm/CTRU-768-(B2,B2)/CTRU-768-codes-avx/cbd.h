#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "params.h"
#include <immintrin.h>
#include "poly.h"


void cbd2(poly * restrict r, const uint8_t buf[CTRU_N/2]);
void cbd3(poly * restrict r, const uint8_t buf[3*CTRU_N/4+8]);

#endif
