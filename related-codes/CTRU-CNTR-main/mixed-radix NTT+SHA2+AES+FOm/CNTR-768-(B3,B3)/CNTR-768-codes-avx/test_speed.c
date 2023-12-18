#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "kem.h"
#include "params.h"
#include "ctru.h"
#include "poly.h"
#include "cpucycles.h"
#include "speed.h"
#include "randombytes.h"

#define NTESTS 10000

uint64_t t[NTESTS];

void test_speed_kem()
{
  printf("\n");

  printf("CTRU-%d-%d-KEM\n\n", CTRU_N, CTRU_Q);

  unsigned int i;
  unsigned char pk[CTRU_KEM_PUBLICKEYBYTES] __attribute__((aligned(32))), sk[CTRU_KEM_SECRETKEYBYTES] __attribute__((aligned(32))), ct[CTRU_KEM_CIPHERTEXTBYTES] __attribute__((aligned(32)));
  unsigned char k1[CTRU_SHAREDKEYBYTES] __attribute__((aligned(32))), k2[CTRU_SHAREDKEYBYTES] __attribute__((aligned(32)));
  for (i = 0; i < NTESTS; i++)
  {
    t[i] = cpucycles();
    crypto_kem_keygen(pk, sk);
  }
  print_results("ctru_kem_keygen: ", t, NTESTS);

  for (i = 0; i < NTESTS; i++)
  {
    t[i] = cpucycles();
    crypto_kem_encaps(ct, k1, pk);
  }
  print_results("ctru_kem_encaps: ", t, NTESTS);

  for (i = 0; i < NTESTS; i++)
  {
    t[i] = cpucycles();
    crypto_kem_decaps(k2, ct, sk);
  }
  print_results("ctru_kem_decaps: ", t, NTESTS);
}

int main()
{
  test_speed_kem();
  return 0;
}
