#include "consts.h"
.macro fqmul l1,l2,h,r
#mul
vpmullw		%ymm\l1,%ymm\h,%ymm\r
vpmulhw		%ymm\l2,%ymm\h,%ymm\h
#reduce
vpmulhw		%ymm0,%ymm\r,%ymm\r
vpsubw		%ymm\r,%ymm\h,%ymm\r
.endm

.text
.global frommont_avx
frommont_avx:
vmovdqa    _16xqinvv(%rip),%ymm1
vmovdqa    _16x1(%rip),%ymm2
vmovdqa    _16xq(%rip),%ymm0
xor    %rax,%rax
_loopfm:
vmovdqa    (%rdi),%ymm3
vmovdqa    (32)(%rdi),%ymm4
vmovdqa    (64)(%rdi),%ymm5
vmovdqa    (96)(%rdi),%ymm6
vmovdqa    (128)(%rdi),%ymm7
vmovdqa    (160)(%rdi),%ymm8
vmovdqa    (192)(%rdi),%ymm9
vmovdqa    (224)(%rdi),%ymm10

fqmul      1,2,3,11
fqmul      1,2,4,3
fqmul      1,2,5,4
fqmul      1,2,6,5
fqmul      1,2,7,6
fqmul      1,2,8,7
fqmul      1,2,9,8
fqmul      1,2,10,9

vmovdqa    %ymm11,(%rdi)
vmovdqa    %ymm3,32(%rdi)
vmovdqa    %ymm4,64(%rdi)
vmovdqa    %ymm5,96(%rdi)
vmovdqa    %ymm6,128(%rdi)
vmovdqa    %ymm7,160(%rdi)
vmovdqa    %ymm8,192(%rdi)
vmovdqa    %ymm9,224(%rdi)


add        $256,%rdi
add        $1,%rax
cmp        $6,%rax
jb         _loopfm



ret