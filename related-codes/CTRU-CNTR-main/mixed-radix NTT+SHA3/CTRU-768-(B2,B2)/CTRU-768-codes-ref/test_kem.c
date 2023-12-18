#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "params.h"
#include "kem.h"

#define NTESTS 10000

void test_kem()
{
  unsigned int i, j;
  unsigned char k1[CTRU_SHAREDKEYBYTES], k2[CTRU_SHAREDKEYBYTES];
  unsigned char pk[CTRU_KEM_PUBLICKEYBYTES], sk[CTRU_KEM_SECRETKEYBYTES];
  unsigned char ct[CTRU_KEM_CIPHERTEXTBYTES];

  for (i = 0; i < NTESTS; i++)
  {
    crypto_kem_keygen(pk, sk);
    crypto_kem_encaps(ct, k1, pk);
    crypto_kem_decaps(k2, ct, sk);

    for (j = 0; j < CTRU_SHAREDKEYBYTES; j++)
      if (k1[j] != k2[j])
      {
        printf("Round %d. Failure: Keys dont match: %hhx != %hhx!\n", i, k1[j], k2[j]);
        return;
      }
  }

  printf("CTRU-%d-KEM is correct!\n", CTRU_N);

  printf("Test %d times.\n\n", NTESTS);
  printf("CTRU_N = %d, CTRU_Q = %d, CTRU_Q2 = %d\n", CTRU_N, CTRU_Q, CTRU_Q2);
  printf("KEM size: pk = %d bytes, ct = %d bytes\n\n",
         CTRU_KEM_PUBLICKEYBYTES, CTRU_KEM_CIPHERTEXTBYTES);
}

int main()
{
  test_kem();
  return 0;
}
