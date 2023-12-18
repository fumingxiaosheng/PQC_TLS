#include <stddef.h>
#include "randombytes.h"
#include "params.h"
#include "ctru.h"
#include "poly.h"
#include "pack.h"
#include "crypto_hash_sha3256.h"


int crypto_kem_keygen(unsigned char *pk,
                      unsigned char *sk)
{
  unsigned int i;
  unsigned char coins[CTRU_N];

  do
  {
    randombytes(coins, CTRU_SEEDBYTES);
    crypto_hash_shake256(coins, CTRU_N, coins, CTRU_SEEDBYTES);
  } while (ctru_keygen(pk, sk, coins));

  for (i = 0; i < CTRU_PKE_PUBLICKEYBYTES; ++i)
    sk[i + CTRU_PKE_SECRETKEYBYTES] = pk[i];

  randombytes(sk + CTRU_PKE_SECRETKEYBYTES + CTRU_PKE_PUBLICKEYBYTES, CTRU_SEEDBYTES);

  return 0;
}

int crypto_kem_encaps(unsigned char *ct,
                      unsigned char *k,
                      const unsigned char *pk)
{
  unsigned int i;
  unsigned char buf[CTRU_SHAREDKEYBYTES + CTRU_N], m[CTRU_PREFIXHASHBYTES + CTRU_MSGBYTES];

  randombytes(buf, CTRU_SEEDBYTES);
  crypto_hash_shake256(m + CTRU_PREFIXHASHBYTES, CTRU_MSGBYTES, buf, 32);
  for (i = 0; i < CTRU_PREFIXHASHBYTES; ++i)
    m[i] = pk[i];
  crypto_hash_sha3512(buf, m, CTRU_PREFIXHASHBYTES + CTRU_MSGBYTES);
  crypto_hash_shake256(buf + CTRU_SHAREDKEYBYTES, CTRU_N, buf + CTRU_SHAREDKEYBYTES, 32);
 
  ctru_enc(ct, pk, m + CTRU_PREFIXHASHBYTES, buf + CTRU_SHAREDKEYBYTES);

  for (i = 0; i < CTRU_SHAREDKEYBYTES; ++i)
    k[i] = buf[i];

  return 0;
}

int crypto_kem_decaps(unsigned char *k,
                      const unsigned char *ct,
                      const unsigned char *sk)
{
  unsigned int i;
  unsigned char buf[CTRU_SHAREDKEYBYTES + CTRU_N], buf2[CTRU_SHAREDKEYBYTES * 2], m[CTRU_PREFIXHASHBYTES + CTRU_MSGBYTES];
  unsigned char ct2[CTRU_PKE_CIPHERTEXTBYTES + CTRU_SEEDBYTES + CTRU_PREFIXHASHBYTES];
  int16_t t;
  int32_t fail;

  ctru_dec(m + CTRU_PREFIXHASHBYTES, ct, sk);

  for (i = 0; i < CTRU_PREFIXHASHBYTES; ++i)
    m[i] = sk[i + CTRU_PKE_SECRETKEYBYTES];

  crypto_hash_sha3512(buf, m, CTRU_PREFIXHASHBYTES + CTRU_MSGBYTES);
  crypto_hash_shake256(buf + CTRU_SHAREDKEYBYTES, CTRU_N, buf + CTRU_SHAREDKEYBYTES,32);

  ctru_enc(ct2, sk + CTRU_PKE_SECRETKEYBYTES, m + CTRU_PREFIXHASHBYTES, buf + CTRU_SHAREDKEYBYTES);

  t = 0;
  for (i = 0; i < CTRU_PKE_CIPHERTEXTBYTES; ++i)
    t |= ct[i] ^ ct2[i];

  fail = (uint16_t)t;
  fail = (-fail) >> 31;

  for (i = 0; i < CTRU_PREFIXHASHBYTES; ++i)
    ct2[i] = sk[i + CTRU_PKE_SECRETKEYBYTES];
  for (i = 0; i < CTRU_SEEDBYTES; ++i)
    ct2[i + CTRU_PREFIXHASHBYTES] = sk[i + CTRU_PKE_SECRETKEYBYTES + CTRU_PKE_PUBLICKEYBYTES];
  for (i = 0; i < CTRU_PKE_CIPHERTEXTBYTES; ++i)
    ct2[i + CTRU_PREFIXHASHBYTES + CTRU_SEEDBYTES] = ct[i];
  crypto_hash_sha3512(buf2, ct2, CTRU_PKE_CIPHERTEXTBYTES + CTRU_SEEDBYTES + CTRU_PREFIXHASHBYTES);

  for (i = 0; i < CTRU_SHAREDKEYBYTES; ++i)
    k[i] = buf[i] ^ ((-fail) & (buf[i] ^ buf2[i]));

  return fail;
}
