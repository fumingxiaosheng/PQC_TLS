#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

void cbd2(poly *r, const uint8_t buf[CTRU_N / 2]);

#endif
