#include "consts.h"

.macro polypack l0,l1,l2,l3,rh0,rh1,rh2
vpsllw     $12,%ymm\l1,%ymm15
vpor       %ymm15,%ymm\l0,%ymm\rh0
vpsllw     $8,%ymm\l2,%ymm15
vpsrlw     $4,%ymm\l1,%ymm\l1
vpor       %ymm\l1,%ymm15,%ymm\rh1
vpsrlw     $8,%ymm\l2,%ymm\l2
vpsllw     $4,%ymm\l3,%ymm\l3
vpor       %ymm\l2,%ymm\l3,%ymm\rh2
.endm
.macro polyunpack l0,l1,l2,rh0,rh1,rh2,rh3
vpand     %ymm\l0,%ymm15,%ymm\rh0
vpsrlw    $12,%ymm\l0,%ymm\l0
vpsllw    $4,%ymm\l1,%ymm14
vpor      %ymm\l0,%ymm14,%ymm\rh1
vpand     %ymm\rh1,%ymm15,%ymm\rh1
vpsrlw    $8,%ymm\l1,%ymm\l1
vpsllw    $8,%ymm\l2,%ymm14
vpor      %ymm\l1,%ymm14,%ymm\rh2
vpand     %ymm15,%ymm\rh2,%ymm\rh2
vpsrlw    $4,%ymm\l2,%ymm\l2
vpand     %ymm\l2,%ymm15,%ymm\rh3
.endm

.macro polypacksk l0,l1,l2,l3,rh0
vpsllw     $4,%ymm\l1,%ymm\l1
vpsllw     $8,%ymm\l2,%ymm\l2
vpsllw     $12,%ymm\l3,%ymm\l3
vpor       %ymm\l0,%ymm\l1,%ymm\l0
vpor       %ymm\l0,%ymm\l2,%ymm\l0
vpor       %ymm\l0,%ymm\l3,%ymm\rh0
.endm

.macro polyunpacksk l,rh0,rh1,rh2,rh3
vpand       %ymm15,%ymm\l,%ymm\rh0
vpsrlw      $4,%ymm\l,%ymm\rh1
vpand       %ymm15,%ymm\rh1,%ymm\rh1
vpsrlw      $8,%ymm\l,%ymm\rh2
vpand       %ymm15,%ymm\rh2,%ymm\rh2
vpsrlw      $12,%ymm\l,%ymm\rh3
vpand       %ymm15,%ymm\rh3,%ymm\rh3
.endm

.text
.global packpk_avx
packpk_avx:

xor    %rcx,%rcx
.p2align 5
_loop_packpk:
vmovdqa    (%rsi),%ymm0
vmovdqa    32(%rsi),%ymm1
vmovdqa    64(%rsi),%ymm2
vmovdqa    96(%rsi),%ymm3
vmovdqa    128(%rsi),%ymm4
vmovdqa    160(%rsi),%ymm5
vmovdqa    192(%rsi),%ymm6
vmovdqa    224(%rsi),%ymm7


polypack       0,1,2,3,8,9,10
polypack       4,5,6,7,11,12,13

vmovdqu    %ymm8,(%rdi)
vmovdqu    %ymm9,32(%rdi)
vmovdqu    %ymm10,64(%rdi)
vmovdqu    %ymm11,96(%rdi)
vmovdqu    %ymm12,128(%rdi)
vmovdqu    %ymm13,160(%rdi)

add   $192,%rdi
add   $256,%rsi
add   $1,%rcx
cmp   $6,%rcx
jb _loop_packpk
ret




.global unpackpk_avx
unpackpk_avx:

xor    %rcx,%rcx
vmovdqu     _16x12bit(%rip),%ymm15
.p2align 5
_loop_unpackpk:
vmovdqu    (%rsi),%ymm0
vmovdqu    32(%rsi),%ymm1
vmovdqu    64(%rsi),%ymm2
vmovdqu    96(%rsi),%ymm3
vmovdqu    128(%rsi),%ymm4
vmovdqu    160(%rsi),%ymm5

polyunpack  0,1,2,6,7,8,9
polyunpack  3,4,5,10,11,12,13


vmovdqa    %ymm6,(%rdi)
vmovdqa    %ymm7,32(%rdi)
vmovdqa    %ymm8,64(%rdi)
vmovdqa    %ymm9,96(%rdi)
vmovdqa    %ymm10,128(%rdi)
vmovdqa    %ymm11,160(%rdi)
vmovdqa    %ymm12,192(%rdi)
vmovdqa    %ymm13,224(%rdi)


add   $192,%rsi
add   $256,%rdi
add   $1,%rcx
cmp   $6,%rcx
jb _loop_unpackpk
ret


.global packsk_avx
packsk_avx:

xor    %rcx,%rcx
.p2align 5
_loop_packsk:
vmovdqa    (%rsi),%ymm0
vmovdqa    32(%rsi),%ymm1
vmovdqa    64(%rsi),%ymm2
vmovdqa    96(%rsi),%ymm3
vmovdqa    128(%rsi),%ymm4
vmovdqa    160(%rsi),%ymm5
vmovdqa    192(%rsi),%ymm6
vmovdqa    224(%rsi),%ymm7

vmovdqu     _16xbound(%rip),%ymm15
vpsubw     %ymm0,%ymm15,%ymm0
vpsubw     %ymm1,%ymm15,%ymm1
vpsubw     %ymm2,%ymm15,%ymm2
vpsubw     %ymm3,%ymm15,%ymm3
vpsubw     %ymm4,%ymm15,%ymm4
vpsubw     %ymm5,%ymm15,%ymm5
vpsubw     %ymm6,%ymm15,%ymm6
vpsubw     %ymm7,%ymm15,%ymm7


polypacksk    0,1,2,3,8
polypacksk    4,5,6,7,9 


vmovdqu    %ymm8,(%rdi)
vmovdqu    %ymm9,32(%rdi)


add   $64,%rdi
add   $256,%rsi
add   $1,%rcx
cmp   $6,%rcx
jb _loop_packsk
ret


.global unpacksk_avx
unpacksk_avx:

xor    %rcx,%rcx
.p2align 5
_loop_unpacksk:
vmovdqa    (%rsi),%ymm0
vmovdqa    32(%rsi),%ymm1


vmovdqu     _16x4bit(%rip),%ymm15


polyunpacksk   0,2,3,4,5
polyunpacksk   1,6,7,8,9



vmovdqu     _16xbound(%rip),%ymm15
vpsubw     %ymm2,%ymm15,%ymm2
vpsubw     %ymm3,%ymm15,%ymm3
vpsubw     %ymm4,%ymm15,%ymm4
vpsubw     %ymm5,%ymm15,%ymm5
vpsubw     %ymm6,%ymm15,%ymm6
vpsubw     %ymm7,%ymm15,%ymm7
vpsubw     %ymm8,%ymm15,%ymm8
vpsubw     %ymm9,%ymm15,%ymm9


vmovdqu    %ymm2,(%rdi)
vmovdqu    %ymm3,32(%rdi)
vmovdqu    %ymm4,64(%rdi)
vmovdqu    %ymm5,96(%rdi)
vmovdqu    %ymm6,128(%rdi)
vmovdqu    %ymm7,160(%rdi)
vmovdqu    %ymm8,192(%rdi)
vmovdqu    %ymm9,224(%rdi)


add   $256,%rdi
add   $64,%rsi
add   $1,%rcx
cmp   $6,%rcx
jb _loop_unpacksk
ret



.global packct_avx
packct_avx:

xor    %rcx,%rcx
.p2align 5
_loop_packct:
vmovdqa    (%rsi),%ymm0
vmovdqa    32(%rsi),%ymm1
vmovdqa    64(%rsi),%ymm2
vmovdqa    96(%rsi),%ymm3
vmovdqa    128(%rsi),%ymm4
vmovdqa    160(%rsi),%ymm5
vmovdqa    192(%rsi),%ymm6
vmovdqa    224(%rsi),%ymm7

vpsllw     $10,%ymm1,%ymm8
vpor       %ymm0,%ymm8,%ymm8
vpsrlw     $6,%ymm1,%ymm1
vpsllw     $4,%ymm2,%ymm2
vpsllw     $14,%ymm3,%ymm9
vpor       %ymm1,%ymm2,%ymm1
vpor       %ymm1,%ymm9,%ymm9
vpsrlw     $2,%ymm3,%ymm3
vpsllw     $8,%ymm4,%ymm10
vpor       %ymm3,%ymm10,%ymm10
vpsrlw     $8,%ymm4,%ymm4
vpsllw     $2,%ymm5,%ymm5
vpsllw     $12,%ymm6,%ymm11
vpor       %ymm4,%ymm5,%ymm4
vpor       %ymm4,%ymm11,%ymm11
vpsrlw     $4,%ymm6,%ymm6
vpsllw     $6,%ymm7,%ymm7
vpor       %ymm6,%ymm7,%ymm12


vmovdqu    %ymm8,(%rdi)
vmovdqu    %ymm9,32(%rdi)
vmovdqu    %ymm10,64(%rdi)
vmovdqu    %ymm11,96(%rdi)
vmovdqu    %ymm12,128(%rdi)


add   $256,%rsi
add   $160,%rdi
add   $1,%rcx
cmp   $6,%rcx
jb _loop_packct
ret



.global unpackct_avx
unpackct_avx:

xor    %rcx,%rcx
.p2align 5
_loop_unpackct:
vmovdqa    (%rsi),%ymm0
vmovdqa    32(%rsi),%ymm1
vmovdqa    64(%rsi),%ymm2
vmovdqa    96(%rsi),%ymm3
vmovdqa    128(%rsi),%ymm4

vmovdqu     _16x10bit(%rip),%ymm15


vpand       %ymm15,%ymm0,%ymm5
vpsrlw      $10,%ymm0,%ymm0
vpsllw      $6,%ymm1,%ymm6
vpor        %ymm0,%ymm6,%ymm6
vpand       %ymm15,%ymm6,%ymm6
vpsrlw      $4,%ymm1,%ymm7
vpand       %ymm15,%ymm7,%ymm7
vpsrlw      $14,%ymm1,%ymm1
vpsllw      $2,%ymm2,%ymm8
vpor        %ymm1,%ymm8,%ymm8
vpand       %ymm15,%ymm8,%ymm8
vpsrlw      $8,%ymm2,%ymm2
vpsllw      $8,%ymm3,%ymm9
vpor        %ymm2,%ymm9,%ymm9
vpand       %ymm15,%ymm9,%ymm9
vpsrlw      $2,%ymm3,%ymm10
vpand       %ymm15,%ymm10,%ymm10
vpsrlw      $12,%ymm3,%ymm3
vpsllw      $4,%ymm4,%ymm11
vpor        %ymm3,%ymm11,%ymm11
vpand       %ymm15,%ymm11,%ymm11
vpsrlw      $6,%ymm4,%ymm4
vpand       %ymm15,%ymm4,%ymm12


vmovdqa    %ymm5,(%rdi)
vmovdqa    %ymm6,32(%rdi)
vmovdqa    %ymm7,64(%rdi)
vmovdqa    %ymm8,96(%rdi)
vmovdqa    %ymm9,128(%rdi)
vmovdqa    %ymm10,160(%rdi)
vmovdqa    %ymm11,192(%rdi)
vmovdqa    %ymm12,224(%rdi)


add   $256,%rdi
add   $160,%rsi
add   $1,%rcx
cmp   $6,%rcx
jb _loop_unpackct
ret