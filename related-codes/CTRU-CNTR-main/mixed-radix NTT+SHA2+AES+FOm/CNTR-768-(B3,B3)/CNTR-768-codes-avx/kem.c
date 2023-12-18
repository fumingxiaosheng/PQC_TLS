#include <stddef.h>
#include "randombytes.h"
#include "params.h"
#include "ctru.h"
#include "poly.h"
#include "pack.h"
#include "crypto_hash_sha3256.h"
#include "crypto_stream.h"
#include "sha2.h"
static const unsigned char nonce[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
#define hash_h(OUT, IN, INBYTES) sha512(OUT, IN, INBYTES);
int crypto_kem_keygen(unsigned char *pk,
                      unsigned char *sk)
{
  unsigned int i;
  unsigned char coins[CTRU_COIN_BYTES];

  do
  {
    randombytes(coins, CTRU_SEEDBYTES);
    crypto_stream(coins, CTRU_COIN_BYTES, nonce, coins);
  } while (ctru_keygen(pk, sk, coins));

  for (i = 0; i < CTRU_PKE_PUBLICKEYBYTES; ++i)
    sk[i + CTRU_PKE_SECRETKEYBYTES] = pk[i];


  return 0;
}

int crypto_kem_encaps(unsigned char *ct,
                      unsigned char *k,
                      const unsigned char *pk)
{
  unsigned int i;
  unsigned char buf[CTRU_SHAREDKEYBYTES + CTRU_COIN_BYTES / 2], m[CTRU_MSGBYTES];

  randombytes(buf, CTRU_SEEDBYTES);
  crypto_stream(m, CTRU_MSGBYTES, nonce, buf);
  hash_h(buf, m, CTRU_MSGBYTES);
  crypto_stream(buf + CTRU_SHAREDKEYBYTES, CTRU_COIN_BYTES / 2, nonce, buf + CTRU_SHAREDKEYBYTES);
  ctru_enc(ct, pk, m, buf + CTRU_SHAREDKEYBYTES);

  for (i = 0; i < CTRU_SHAREDKEYBYTES; ++i)
    k[i] = buf[i];

  return 0;
}

int crypto_kem_decaps(unsigned char *k,
                      const unsigned char *ct,
                      const unsigned char *sk)
{
  unsigned int i;
  unsigned char buf[CTRU_SHAREDKEYBYTES + CTRU_COIN_BYTES / 2], m[CTRU_MSGBYTES];
  unsigned char ct2[CTRU_PKE_CIPHERTEXTBYTES];
  int16_t t;
  int32_t fail;

  ctru_dec(m, ct, sk);

  hash_h(buf, m, CTRU_MSGBYTES);
  crypto_stream(buf + CTRU_SHAREDKEYBYTES, CTRU_COIN_BYTES / 2, nonce, buf + CTRU_SHAREDKEYBYTES);


  ctru_enc(ct2, sk + CTRU_PKE_SECRETKEYBYTES, m, buf + CTRU_SHAREDKEYBYTES);


  t = 0;
  for (i = 0; i < CTRU_PKE_CIPHERTEXTBYTES; ++i)
    t |= ct[i] ^ ct2[i];

  fail = (uint16_t)t;
  fail = (-fail) >> 31;

  for (i = 0; i < CTRU_SHAREDKEYBYTES; ++i)
    k[i] = buf[i] & ~(-fail);
  return fail;
}
