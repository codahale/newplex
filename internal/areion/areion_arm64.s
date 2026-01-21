//go:build arm64 && !nosimd

#include "textflag.h"

// func permute512Asm(state *[64]byte)
TEXT ·permute512Asm(SB), NOSPLIT, $0
	MOVD state+0(FP), R0
	
VLD1 (R0), [V0.B16]
	ADD $16, R0, R3
	VLD1 (R3), [V1.B16]
	ADD $16, R3, R3
	VLD1 (R3), [V2.B16]
	ADD $16, R3, R3
	VLD1 (R3), [V3.B16]
	
	VEOR V16.B16, V16.B16, V16.B16 // zero

	// Load roundConstants address
	MOVD $·roundConstants(SB), R1
	
	// ROUND macro
	// s0, s1, s2, s3: Vectors V0-V3 (or rotated)
	// offset: integer offset
	// Uses V4, V5 scratch. V16 zero.
#define ROUND(s0, s1, s2, s3, offset) \
	MOVD $offset, R2; \
	ADD R2, R1, R2; \
	VLD1 (R2), [V5.B16]; /* Load RC */ \
	VORR s0.B16, s0.B16, V4.B16; /* tmp = s0 */ \
	AESE V16.B16, V4.B16; /* tmp = SB(SR(tmp)) */ \
	AESMC V4.B16, V4.B16; /* tmp = MC(tmp) */ \
	VEOR s1.B16, V4.B16, s1.B16; /* s1 = s1 ^ tmp = s1 ^ F0(s0) */ \
	VORR s2.B16, s2.B16, V4.B16; /* tmp = s2 */ \
	AESE V16.B16, V4.B16; /* tmp = SB(SR(tmp)) */ \
	AESMC V4.B16, V4.B16; /* tmp = MC(tmp) */ \
	VEOR s3.B16, V4.B16, V4.B16; /* tmp = s3 ^ F0(s2) */ \
	AESE V16.B16, s2.B16; /* s2 = SB(SR(s2)) ^ 0 */ \
	VEOR V5.B16, s2.B16, s2.B16; /* s2 = s2 ^ RC */ \
	AESE V16.B16, s2.B16; /* s2 = SB(SR(s2)) ^ 0 */ \
	AESMC s2.B16, s2.B16; /* s2 = MC(...) */ \
	AESE V16.B16, s0.B16; /* s0 = SB(SR(s0)) ^ 0 (AESENCLAST) */ \
	VORR V4.B16, V4.B16, s3.B16; /* s3 = tmp */

	// Unroll 15 rounds
	ROUND(V0, V1, V2, V3, 0)
	ROUND(V1, V2, V3, V0, 16)
	ROUND(V2, V3, V0, V1, 32)
	ROUND(V3, V0, V1, V2, 48)
	ROUND(V0, V1, V2, V3, 64)
	ROUND(V1, V2, V3, V0, 80)
	ROUND(V2, V3, V0, V1, 96)
	ROUND(V3, V0, V1, V2, 112)
	ROUND(V0, V1, V2, V3, 128)
	ROUND(V1, V2, V3, V0, 144)
	ROUND(V2, V3, V0, V1, 160)
	ROUND(V3, V0, V1, V2, 176)
	ROUND(V0, V1, V2, V3, 192)
	ROUND(V1, V2, V3, V0, 208)
	ROUND(V2, V3, V0, V1, 224)

	MOVD state+0(FP), R0
	VST1 [V3.B16], (R0)
	ADD $16, R0, R3
	VST1 [V0.B16], (R3)
	ADD $16, R3, R3
	VST1 [V1.B16], (R3)
	ADD $16, R3, R3
	VST1 [V2.B16], (R3)
	RET

// Same constants as AMD64
DATA ·roundConstants+0(SB)/4, $0x03707344
DATA ·roundConstants+4(SB)/4, $0x13198a2e
DATA ·roundConstants+8(SB)/4, $0x85a308d3
DATA ·roundConstants+12(SB)/4, $0x243f6a88
DATA ·roundConstants+16(SB)/4, $0xec4e6c89
DATA ·roundConstants+20(SB)/4, $0x082efa98
DATA ·roundConstants+24(SB)/4, $0x299f31d0
DATA ·roundConstants+28(SB)/4, $0xa4093822
DATA ·roundConstants+32(SB)/4, $0x34e90c6c
DATA ·roundConstants+36(SB)/4, $0xbe5466cf
DATA ·roundConstants+40(SB)/4, $0x38d01377
DATA ·roundConstants+44(SB)/4, $0x452821e6
DATA ·roundConstants+48(SB)/4, $0xb5470917
DATA ·roundConstants+52(SB)/4, $0x3f84d5b5
DATA ·roundConstants+56(SB)/4, $0xc97c50dd
DATA ·roundConstants+60(SB)/4, $0xc0ac29b7
DATA ·roundConstants+64(SB)/4, $0x98dfb5ac
DATA ·roundConstants+68(SB)/4, $0xd1310ba6
DATA ·roundConstants+72(SB)/4, $0x8979fb1b
DATA ·roundConstants+76(SB)/4, $0x9216d5d9
DATA ·roundConstants+80(SB)/4, $0x6a267e96
DATA ·roundConstants+84(SB)/4, $0xb8e1afed
DATA ·roundConstants+88(SB)/4, $0xd01adfb7
DATA ·roundConstants+92(SB)/4, $0x2ffd72db
DATA ·roundConstants+96(SB)/4, $0xb3916cf7
DATA ·roundConstants+100(SB)/4, $0x24a19947
DATA ·roundConstants+104(SB)/4, $0xf12c7f99
DATA ·roundConstants+108(SB)/4, $0xba7c9045
DATA ·roundConstants+112(SB)/4, $0x1574e690
DATA ·roundConstants+116(SB)/4, $0x36920d87
DATA ·roundConstants+120(SB)/4, $0x58efc166
DATA ·roundConstants+124(SB)/4, $0x801f2e28
DATA ·roundConstants+128(SB)/4, $0x728eb658
DATA ·roundConstants+132(SB)/4, $0x0d95748f
DATA ·roundConstants+136(SB)/4, $0xf4933d7e
DATA ·roundConstants+140(SB)/4, $0xa458fea3
DATA ·roundConstants+144(SB)/4, $0xc25a59b5
DATA ·roundConstants+148(SB)/4, $0x7b54a41d
DATA ·roundConstants+152(SB)/4, $0x82154aee
DATA ·roundConstants+156(SB)/4, $0x718bcd58
DATA ·roundConstants+160(SB)/4, $0x286085f0
DATA ·roundConstants+164(SB)/4, $0xc5d1b023
DATA ·roundConstants+168(SB)/4, $0x2af26013
DATA ·roundConstants+172(SB)/4, $0x9c30d539
DATA ·roundConstants+176(SB)/4, $0x603a180e
DATA ·roundConstants+180(SB)/4, $0x8e79dcb0
DATA ·roundConstants+184(SB)/4, $0xb8db38ef
DATA ·roundConstants+188(SB)/4, $0xca417918
DATA ·roundConstants+192(SB)/4, $0xbd314b27
DATA ·roundConstants+196(SB)/4, $0xd71577c1
DATA ·roundConstants+200(SB)/4, $0xb01e8a3e
DATA ·roundConstants+204(SB)/4, $0x6c9e0e8b
DATA ·roundConstants+208(SB)/4, $0xaa55ab94
DATA ·roundConstants+212(SB)/4, $0xe65525f3
DATA ·roundConstants+216(SB)/4, $0x55605c60
DATA ·roundConstants+220(SB)/4, $0x78af2fda
DATA ·roundConstants+224(SB)/4, $0x2aab10b6
DATA ·roundConstants+228(SB)/4, $0x55ca396a
DATA ·roundConstants+232(SB)/4, $0x63e81440
DATA ·roundConstants+236(SB)/4, $0x57489862

GLOBL ·roundConstants(SB), (NOPTR+RODATA), $240
