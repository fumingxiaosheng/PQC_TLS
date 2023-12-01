#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "cpucycles.h"
#include "speed.h"
#include "randombytes.h"
#include "params.h"
#include "ctru.h"
#include "poly.h"
#include "ntt.h"

#define NTESTS 10000
#define HISTORY 512

void test_pke()
{
  unsigned int i, j;
  int count = 0;
  unsigned char coins[CTRU_COIN_BYTES * 3 / 2] , m[CTRU_MSGBYTES], m2[CTRU_MSGBYTES];
  unsigned char pk[CTRU_PKE_PUBLICKEYBYTES] __attribute__((aligned(32))), sk[CTRU_PKE_SECRETKEYBYTES] __attribute__((aligned(32))), ct[CTRU_PKE_CIPHERTEXTBYTES] __attribute__((aligned(32)));

  for (i = 0; i < NTESTS; ++i)
  {
    randombytes(coins, sizeof(coins));
    randombytes(m, sizeof(m));

    if (ctru_keygen(pk, sk, coins))
    {
      continue; // It indicates that f^-1 does not exit.
    }
      
    ctru_enc(ct, pk, m, coins + CTRU_COIN_BYTES);
    ctru_dec(m2, ct, sk);
    for (j = 0; j < CTRU_MSGBYTES; ++j)
      if (m[j] != m2[j])
      {
        printf("Round %d. Messages don't match: m[%u] = %hd != %hd\n", i, j, m[j], m2[j]);
        return;
      }
    count++;
    
  }

  printf("CTRU-PKE is correct!\n");

  printf("Test %d times.\n\n", count);
  printf("CTRU_N = %d,CTRU_Q2 = %d\n", CTRU_N, CTRU_Q2);
  printf("PKE size: pk = %d bytes, ct = %d bytes, sk = %d bytes\n\n",
         CTRU_PKE_PUBLICKEYBYTES, CTRU_PKE_CIPHERTEXTBYTES, CTRU_PKE_SECRETKEYBYTES);
}

int main(void)
{
  // test_pke_time();

  test_pke();
  return 0;
}
