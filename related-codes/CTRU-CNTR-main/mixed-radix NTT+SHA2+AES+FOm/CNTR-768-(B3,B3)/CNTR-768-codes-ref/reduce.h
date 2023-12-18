#ifndef REDUCE_H
#define REDUCE_H

#include <stdint.h>

#define MONT 3310
#define QINV 12929
#define v 19412

int16_t montgomery_reduce(int32_t a);
int16_t barrett_reduce(int16_t a);
int16_t fqcsubq(int16_t a);
int16_t fqmul(int16_t a, int16_t b);
int16_t fqinv(int16_t a);
int16_t fquniform();

#endif
