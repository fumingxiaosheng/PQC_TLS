#ifndef CTRU_H
#define CTRU_H

#include "poly.h"

int ctru_keygen(unsigned char pk[CTRU_PKE_PUBLICKEYBYTES],
                unsigned char sk[CTRU_PKE_SECRETKEYBYTES],
                const unsigned char coins[CTRU_N]);
                
void ctru_enc(unsigned char ct[CTRU_PKE_CIPHERTEXTBYTES],
              const unsigned char pk[CTRU_PKE_PUBLICKEYBYTES],
              const unsigned char m[CTRU_MSGBYTES],
              const unsigned char coins[CTRU_N]);

void ctru_dec(unsigned char m[CTRU_MSGBYTES],
              const unsigned char ct[CTRU_PKE_CIPHERTEXTBYTES],
              const unsigned char sk[CTRU_PKE_SECRETKEYBYTES]);

#endif
