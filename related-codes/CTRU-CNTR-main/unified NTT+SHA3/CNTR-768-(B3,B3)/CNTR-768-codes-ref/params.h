#ifndef PARAMS_H
#define PARAMS_H

/* CNTR KEM*/

#ifndef CTRU_ALPHA
#define CTRU_ALPHA 3 /* Change this for different security strengths */
#endif

#define CTRU_Q 3457
#define CTRU_LOGQ 12

#define CTRU_Q 3457
#define CTRU_LOGQ 12

#if (CTRU_ALPHA == 2)
#define CTRU_N 512
#define CTRU_Q2 1024                     /* Change this for the ciphertext modulus */
#define CTRU_LOGQ2 10                    /* Change this for the ciphertext modulus */
#define CTRU_BOUND 11                    /* BOUND = 2 * eta + 1 */
#define CTRU_COIN_BYTES (CTRU_N * 5 / 2) /* COIN_BYTES = (N * 2 * eta) * 2 / 8 */
#elif (CTRU_ALPHA == 3)
#define CTRU_N 768
#define CTRU_Q2 1024                     /* Change this for the ciphertext modulus */
#define CTRU_LOGQ2 10                    /* Change this for the ciphertext modulus */
#define CTRU_BOUND 7                     /* BOUND = 2 * eta + 1 */
#define CTRU_COIN_BYTES (CTRU_N * 3 / 2) /* COIN_BYTES = (N * 2 * eta) * 2 / 8 */
#elif (CTRU_ALPHA == 4)
#define CTRU_N 1024
#define CTRU_Q2 1024           /* Change this for the ciphertext modulus */
#define CTRU_LOGQ2 10          /* Change this for the ciphertext modulus */
#define CTRU_BOUND 5           /* BOUND = 2 * eta + 1 */
#define CTRU_COIN_BYTES CTRU_N /* COIN_BYTES = (N * 2 * eta) * 2 / 8 */
#else
#error "CTRU_ALPHA must be in {2,3,4}"
#endif

#define CTRU_NTT_N 256

#define CTRU_SEEDBYTES 32
#define CTRU_SHAREDKEYBYTES 32
#define CTRU_MSGBYTES (CTRU_N / 16)

#define CTRU_PKE_PUBLICKEYBYTES (CTRU_LOGQ * CTRU_N / 8)
#define CTRU_PKE_CIPHERTEXTBYTES (CTRU_LOGQ2 * CTRU_N / 8)

#if ((CTRU_BOUND == 5) || (CTRU_BOUND == 7))
#define CTRU_PKE_SECRETKEYBYTES (4 * CTRU_N / 8)
#elif (CTRU_BOUND == 11)
#define CTRU_PKE_SECRETKEYBYTES (5 * CTRU_N / 8)
#endif

#define CTRU_KEM_PUBLICKEYBYTES CTRU_PKE_PUBLICKEYBYTES
#define CTRU_KEM_SECRETKEYBYTES (CTRU_PKE_SECRETKEYBYTES + CTRU_PKE_PUBLICKEYBYTES + CTRU_SEEDBYTES)
#define CTRU_KEM_CIPHERTEXTBYTES CTRU_PKE_CIPHERTEXTBYTES
#define CTRU_PREFIXHASHBYTES 33

#endif
