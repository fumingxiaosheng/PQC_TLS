# CTRU and CNTR


The target parameter sets are ($n=768,q=3457,q_2=2^{10},\Psi_1=\Psi_2=B_2$) for CTRU-768 and ($n=768,q=3457,q_2=2^{10},\Psi_1=\Psi_2=B_3$) for CNTR-768.

The folder ''mixed-radix NTT+SHA3'' consists of CTRU-768 and CNTR-768 with mixed-radix NTT and SHA-3 family.

The folder ''mixed-radix NTT+SHA2+AES+FOm'' consists of the variants of CTRU-768 and CNTR-768 with mixed-radix NTT and SHA-2 family.

The folder ''unified NTT+SHA3'' consists of CTRU-768 and CNTR-768 with unified NTT and SHA-3 family.


## The portable C implementation


Please enter the corresponding folders and run the portable C codes.

For example:

Enter the folder: mixed-radix NTT+SHA3 --> CTRU-768-(B2,B2) --> CTRU-768-codes-ref

```
make
./test_kem768
./test_speed768
```

## The optimized AVX2 implementation


Please enter the corresponding folders and run the optimized AVX2 codes.

For example:

Enter the folder: mixed-radix NTT+SHA3 --> CTRU-768-(B2,B2) --> CTRU-768-codes-avx

```
make
./test_kem768
./test_speed768
```


