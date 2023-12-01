#ifndef INVERSE_H
#define INVERSE_H

#include <stdint.h>
#include "params.h"

#define CTRU_MATRIX_N (2 * CTRU_ALPHA)

int rq_inverse(int16_t finv[CTRU_MATRIX_N], const int16_t f[CTRU_MATRIX_N], const int16_t zeta);

#endif