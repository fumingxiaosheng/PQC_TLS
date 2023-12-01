#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

void cbd2(poly *r, const uint8_t buf[]);
void cbd3(poly *r, const uint8_t buf[]);
void cbd4(poly *r, const uint8_t buf[]);
void cbd5(poly *r, const uint8_t buf[]);

#endif
