//go:build amd64 && !nosimd

#include "textflag.h"

// func permute512(state *[64]byte)
TEXT ·permute512(SB), NOSPLIT, $0
	MOVQ state+0(FP), DI
	
    MOVOU 0(DI), X0   // x0
	MOVOU 16(DI), X1  // x1
	MOVOU 32(DI), X2  // x2
	MOVOU 48(DI), X3  // x3
	
    PXOR X15, X15     // zero
	
	// ROUND macro
	// Arguments:
	// s0, s1, s2, s3: Registers holding the current state blocks 0, 1, 2, 3.
	// offset: Offset into roundConstants table (in bytes).
	// Uses X4, X5 as scratch. X15 is zero.
#define ROUND(s0, s1, s2, s3, offset) \
	MOVOU ·roundConstants + offset(SB), X5; \
	MOVOU s0, X4;         /* tmp = s0 */ \
	AESENC s1, X4;        /* tmp = AESENC(tmp, s1) = Transformed(s0) ^ s1 */ \
	MOVOU X4, s1;         /* s1 = tmp */ \
	MOVOU s2, X4;         /* tmp = s2 */ \
	AESENC s3, X4;        /* tmp = AESENC(tmp, s3) = Transformed(s2) ^ s3 */ \
	AESENCLAST X5, s2;    /* s2 = AESENCLAST(s2, RC) */ \
	AESENC X15, s2;       /* s2 = AESENC(s2, 0) */ \
	AESENCLAST X15, s0;   /* s0 = AESENCLAST(s0, 0) */ \
	MOVOU X4, s3;         /* s3 = tmp */

	// Unroll 15 rounds
	ROUND(X0, X1, X2, X3, 0)
	ROUND(X1, X2, X3, X0, 16)
	ROUND(X2, X3, X0, X1, 32)
	ROUND(X3, X0, X1, X2, 48)
	ROUND(X0, X1, X2, X3, 64)
	ROUND(X1, X2, X3, X0, 80)
	ROUND(X2, X3, X0, X1, 96)
	ROUND(X3, X0, X1, X2, 112)
	ROUND(X0, X1, X2, X3, 128)
	ROUND(X1, X2, X3, X0, 144)
	ROUND(X2, X3, X0, X1, 160)
	ROUND(X3, X0, X1, X2, 176)
	ROUND(X0, X1, X2, X3, 192)
	ROUND(X1, X2, X3, X0, 208)
	ROUND(X2, X3, X0, X1, 224)

	MOVOU X3, 0(DI)
	MOVOU X0, 16(DI)
	MOVOU X1, 32(DI)
	MOVOU X2, 48(DI)
	RET

// Round constants for Areion-512
// RC0
DATA ·roundConstants+0(SB)/4, $0x03707344
DATA ·roundConstants+4(SB)/4, $0x13198a2e
DATA ·roundConstants+8(SB)/4, $0x85a308d3
DATA ·roundConstants+12(SB)/4, $0x243f6a88
// RC1
DATA ·roundConstants+16(SB)/4, $0xec4e6c89
DATA ·roundConstants+20(SB)/4, $0x082efa98
DATA ·roundConstants+24(SB)/4, $0x299f31d0
DATA ·roundConstants+28(SB)/4, $0xa4093822
// RC2
DATA ·roundConstants+32(SB)/4, $0x34e90c6c
DATA ·roundConstants+36(SB)/4, $0xbe5466cf
DATA ·roundConstants+40(SB)/4, $0x38d01377
DATA ·roundConstants+44(SB)/4, $0x452821e6
// RC3
DATA ·roundConstants+48(SB)/4, $0xb5470917
DATA ·roundConstants+52(SB)/4, $0x3f84d5b5
DATA ·roundConstants+56(SB)/4, $0xc97c50dd
DATA ·roundConstants+60(SB)/4, $0xc0ac29b7
// RC4
DATA ·roundConstants+64(SB)/4, $0x98dfb5ac
DATA ·roundConstants+68(SB)/4, $0xd1310ba6
DATA ·roundConstants+72(SB)/4, $0x8979fb1b
DATA ·roundConstants+76(SB)/4, $0x9216d5d9
// RC5
DATA ·roundConstants+80(SB)/4, $0x6a267e96
DATA ·roundConstants+84(SB)/4, $0xb8e1afed
DATA ·roundConstants+88(SB)/4, $0xd01adfb7
DATA ·roundConstants+92(SB)/4, $0x2ffd72db
// RC6
DATA ·roundConstants+96(SB)/4, $0xb3916cf7
DATA ·roundConstants+100(SB)/4, $0x24a19947
DATA ·roundConstants+104(SB)/4, $0xf12c7f99
DATA ·roundConstants+108(SB)/4, $0xba7c9045
// RC7
DATA ·roundConstants+112(SB)/4, $0x1574e690
DATA ·roundConstants+116(SB)/4, $0x36920d87
DATA ·roundConstants+120(SB)/4, $0x58efc166
DATA ·roundConstants+124(SB)/4, $0x801f2e28
// RC8
DATA ·roundConstants+128(SB)/4, $0x728eb658
DATA ·roundConstants+132(SB)/4, $0x0d95748f
DATA ·roundConstants+136(SB)/4, $0xf4933d7e
DATA ·roundConstants+140(SB)/4, $0xa458fea3
// RC9
DATA ·roundConstants+144(SB)/4, $0xc25a59b5
DATA ·roundConstants+148(SB)/4, $0x7b54a41d
DATA ·roundConstants+152(SB)/4, $0x82154aee
DATA ·roundConstants+156(SB)/4, $0x718bcd58
// RC10
DATA ·roundConstants+160(SB)/4, $0x286085f0
DATA ·roundConstants+164(SB)/4, $0xc5d1b023
DATA ·roundConstants+168(SB)/4, $0x2af26013
DATA ·roundConstants+172(SB)/4, $0x9c30d539
// RC11
DATA ·roundConstants+176(SB)/4, $0x603a180e
DATA ·roundConstants+180(SB)/4, $0x8e79dcb0
DATA ·roundConstants+184(SB)/4, $0xb8db38ef
DATA ·roundConstants+188(SB)/4, $0xca417918
// RC12
DATA ·roundConstants+192(SB)/4, $0xbd314b27
DATA ·roundConstants+196(SB)/4, $0xd71577c1
DATA ·roundConstants+200(SB)/4, $0xb01e8a3e
DATA ·roundConstants+204(SB)/4, $0x6c9e0e8b
// RC13
DATA ·roundConstants+208(SB)/4, $0xaa55ab94
DATA ·roundConstants+212(SB)/4, $0xe65525f3
DATA ·roundConstants+216(SB)/4, $0x55605c60
DATA ·roundConstants+220(SB)/4, $0x78af2fda
// RC14
DATA ·roundConstants+224(SB)/4, $0x2aab10b6
DATA ·roundConstants+228(SB)/4, $0x55ca396a
DATA ·roundConstants+232(SB)/4, $0x63e81440
DATA ·roundConstants+236(SB)/4, $0x57489862

GLOBL ·roundConstants(SB), (NOPTR+RODATA), $240
