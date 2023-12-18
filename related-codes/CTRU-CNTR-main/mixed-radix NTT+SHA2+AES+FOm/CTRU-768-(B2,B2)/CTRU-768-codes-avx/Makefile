CC ?= /usr/bin/cc
CFLAGS += -Wall -march=native -mtune=native -O3 -fomit-frame-pointer -Wno-unknown-pragmas
LDFLAGS += -lcrypto -ldl

SOURCES = ctru.c poly.c coding.c aes256ctr.c cbd.c fips202.c\
  cpucycles.c speed.c pack.c kem.c consts.c pack.S ntt.S basemul.S invntt.S frommont.S\
  reduce.S double.S basemul7681.S invntt7681.S consts7681.c ntt7681.S add.S \
  fastrandombytes.c kernelrandombytes.c baseinv.S sha256.c sha512.c
HEADERS = params.h ctru.h poly.h ntt.h coding.h fips202.h crypto_hash_sha3256.h\
  crypto_stream.h randombytes.h cpucycles.h speed.h pack.h kem.h cbd.h align.h consts.h kernelrandombytes.h sha2.h
all:  test_pke768 test_kem768 test_speed768 


test_pke768: test_pke.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DCTRU_ALPHA=3 $< $(SOURCES) -o $@ $(LDFLAGS)

test_kem768: test_kem.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DCTRU_ALPHA=3 $< $(SOURCES) -o $@ $(LDFLAGS)

test_speed768: test_speed.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DCTRU_ALPHA=3 $< $(SOURCES) -o $@ $(LDFLAGS)


.PHONY: clean

clean:
	rm -f *~ *~
	rm -f test_kem768
	rm -f test_pke768
	rm -f test_speed768	

