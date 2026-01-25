//go:build arm64 && !purego

#include "textflag.h"

// func permute512(state *[64]byte)
TEXT ·permute512(SB), NOSPLIT, $0
	MOVD state+0(FP), R0
	
	// Load state
	VLD1 (R0), [V0.B16]
	ADD $16, R0, R3
	VLD1 (R3), [V1.B16]
	ADD $16, R3, R3
	VLD1 (R3), [V2.B16]
	ADD $16, R3, R3
	VLD1 (R3), [V3.B16]
	
	MOVD $·rc(SB), R1
	VEOR V16.B16, V16.B16, V16.B16 // zero

#define AES_ROUND(s0, s1, s2, s3, off) \
	MOVD $off, R2; \
	ADD R2, R1, R2; \
	VLD1 (R2), [V4.B16]; \
	AESE V16.B16, s0.B16; \
	AESMC s0.B16, s0.B16; \
	VEOR V4.B16, s0.B16, s0.B16; \
	\
	ADD $16, R2, R2; \
	VLD1 (R2), [V4.B16]; \
	AESE V16.B16, s1.B16; \
	AESMC s1.B16, s1.B16; \
	VEOR V4.B16, s1.B16, s1.B16; \
	\
	ADD $16, R2, R2; \
	VLD1 (R2), [V4.B16]; \
	AESE V16.B16, s2.B16; \
	AESMC s2.B16, s2.B16; \
	VEOR V4.B16, s2.B16, s2.B16; \
	\
	ADD $16, R2, R2; \
	VLD1 (R2), [V4.B16]; \
	AESE V16.B16, s3.B16; \
	AESMC s3.B16, s3.B16; \
	VEOR V4.B16, s3.B16, s3.B16

#define MIX512(s0, s1, s2, s3) \
	/* Transpose 4x4 matrix of 32-bit words using VZIP instructions */ \
	/* t0 (V4) = VZIP1(s0, s2) -> 00 20 01 21 */ \
	VZIP1 s2.S4, s0.S4, V4.S4; \
	/* t1 (V5) = VZIP1(s1, s3) -> 10 30 11 31 */ \
	VZIP1 s3.S4, s1.S4, V5.S4; \
	/* t2 (V6) = VZIP2(s0, s2) -> 02 22 03 23 */ \
	VZIP2 s2.S4, s0.S4, V6.S4; \
	/* t3 (V7) = VZIP2(s1, s3) -> 12 32 13 33 */ \
	VZIP2 s3.S4, s1.S4, V7.S4; \
	\
	/* s0 = VZIP1(t0, t1) -> 00 10 20 30 */ \
	VZIP1 V5.S4, V4.S4, s0.S4; \
	/* s1 = VZIP2(t0, t1) -> 01 11 21 31 */ \
	VZIP2 V5.S4, V4.S4, s1.S4; \
	/* s2 = VZIP1(t2, t3) -> 02 12 22 32 */ \
	VZIP1 V7.S4, V6.S4, s2.S4; \
	/* s3 = VZIP2(t2, t3) -> 03 13 23 33 */ \
	VZIP2 V7.S4, V6.S4, s3.S4

	// Round 0
	AES_ROUND(V0, V1, V2, V3, 0)
	AES_ROUND(V0, V1, V2, V3, 64)
	MIX512(V0, V1, V2, V3)

	// Round 1
	AES_ROUND(V0, V1, V2, V3, 128)
	AES_ROUND(V0, V1, V2, V3, 192)
	MIX512(V0, V1, V2, V3)

	// Round 2
	AES_ROUND(V0, V1, V2, V3, 256)
	AES_ROUND(V0, V1, V2, V3, 320)
	MIX512(V0, V1, V2, V3)

	// Round 3 (RC 0-7)
	AES_ROUND(V0, V1, V2, V3, 0)
	AES_ROUND(V0, V1, V2, V3, 64)
	MIX512(V0, V1, V2, V3)

	// Round 4 (RC 8-15)
	AES_ROUND(V0, V1, V2, V3, 128)
	AES_ROUND(V0, V1, V2, V3, 192)
	MIX512(V0, V1, V2, V3)

	// Round 5 (RC 16-23)
	AES_ROUND(V0, V1, V2, V3, 256)
	AES_ROUND(V0, V1, V2, V3, 320)
	MIX512(V0, V1, V2, V3)

	MOVD state+0(FP), R0
	VST1 [V0.B16], (R0)
	ADD $16, R0, R3
	VST1 [V1.B16], (R3)
	ADD $16, R3, R3
	VST1 [V2.B16], (R3)
	ADD $16, R3, R3
	VST1 [V3.B16], (R3)
	RET

// Same constants as AMD64
DATA ·rc+0(SB)/4, $0x0684704c; DATA ·rc+4(SB)/4, $0xe620c00a; DATA ·rc+8(SB)/4, $0xb2c5fef0; DATA ·rc+12(SB)/4, $0x75817b9d
DATA ·rc+16(SB)/4, $0x8b66b4e1; DATA ·rc+20(SB)/4, $0x88f3a06b; DATA ·rc+24(SB)/4, $0x640f6ba4; DATA ·rc+28(SB)/4, $0x2f08f717
DATA ·rc+32(SB)/4, $0x3402de2d; DATA ·rc+36(SB)/4, $0x53f28498; DATA ·rc+40(SB)/4, $0xcf029d60; DATA ·rc+44(SB)/4, $0x9f029114
DATA ·rc+48(SB)/4, $0x0ed6eae6; DATA ·rc+52(SB)/4, $0x2e7b4f08; DATA ·rc+56(SB)/4, $0xbbf3bcaf; DATA ·rc+60(SB)/4, $0xfd5b4f79
DATA ·rc+64(SB)/4, $0xcbcfb0cb; DATA ·rc+68(SB)/4, $0x4872448b; DATA ·rc+72(SB)/4, $0x79eecd1c; DATA ·rc+76(SB)/4, $0xbe397044
DATA ·rc+80(SB)/4, $0x7eeacdee; DATA ·rc+84(SB)/4, $0x6e9032b7; DATA ·rc+88(SB)/4, $0x8d5335ed; DATA ·rc+92(SB)/4, $0x2b8a057b
DATA ·rc+96(SB)/4, $0x67c28f43; DATA ·rc+100(SB)/4, $0x5e2e7cd0; DATA ·rc+104(SB)/4, $0xe2412761; DATA ·rc+108(SB)/4, $0xda4fef1b
DATA ·rc+112(SB)/4, $0x2924d9b0; DATA ·rc+116(SB)/4, $0xafcacc07; DATA ·rc+120(SB)/4, $0x675ffde2; DATA ·rc+124(SB)/4, $0x1fc70b3b
DATA ·rc+128(SB)/4, $0xab4d63f1; DATA ·rc+132(SB)/4, $0xe6867fe9; DATA ·rc+136(SB)/4, $0xecdb8fca; DATA ·rc+140(SB)/4, $0xb9d465ee
DATA ·rc+144(SB)/4, $0x1c30bf84; DATA ·rc+148(SB)/4, $0xd4b7cd64; DATA ·rc+152(SB)/4, $0x5b2a404f; DATA ·rc+156(SB)/4, $0xad037e33
DATA ·rc+160(SB)/4, $0xb2cc0bb9; DATA ·rc+164(SB)/4, $0x941723bf; DATA ·rc+168(SB)/4, $0x69028b2e; DATA ·rc+172(SB)/4, $0x8df69800
DATA ·rc+176(SB)/4, $0xfa0478a6; DATA ·rc+180(SB)/4, $0xde6f5572; DATA ·rc+184(SB)/4, $0x4aaa9ec8; DATA ·rc+188(SB)/4, $0x5c9d2d8a
DATA ·rc+192(SB)/4, $0xdfb49f2b; DATA ·rc+196(SB)/4, $0x6b772a12; DATA ·rc+200(SB)/4, $0x0efa4f2e; DATA ·rc+204(SB)/4, $0x29129fd4
DATA ·rc+208(SB)/4, $0x1ea10344; DATA ·rc+212(SB)/4, $0xf449a236; DATA ·rc+216(SB)/4, $0x32d611ae; DATA ·rc+220(SB)/4, $0xbb6a12ee
DATA ·rc+224(SB)/4, $0xaf044988; DATA ·rc+228(SB)/4, $0x4b050084; DATA ·rc+232(SB)/4, $0x5f9600c9; DATA ·rc+236(SB)/4, $0x9ca8eca6
DATA ·rc+240(SB)/4, $0x21025ed8; DATA ·rc+244(SB)/4, $0x9d199c4f; DATA ·rc+248(SB)/4, $0x78a2c7e3; DATA ·rc+252(SB)/4, $0x27e593ec
DATA ·rc+256(SB)/4, $0xbf3aaaf8; DATA ·rc+260(SB)/4, $0xa759c9b7; DATA ·rc+264(SB)/4, $0xb9282ecd; DATA ·rc+268(SB)/4, $0x82d40173
DATA ·rc+272(SB)/4, $0x6260700d; DATA ·rc+276(SB)/4, $0x6186b017; DATA ·rc+280(SB)/4, $0x37f2efd9; DATA ·rc+284(SB)/4, $0x10307d6b
DATA ·rc+288(SB)/4, $0x5aca45c2; DATA ·rc+292(SB)/4, $0x21300443; DATA ·rc+296(SB)/4, $0x81c29153; DATA ·rc+300(SB)/4, $0xf6fc9ac6
DATA ·rc+304(SB)/4, $0x9223973c; DATA ·rc+308(SB)/4, $0x226b68bb; DATA ·rc+312(SB)/4, $0x2caf92e8; DATA ·rc+316(SB)/4, $0x36d1943a
DATA ·rc+320(SB)/4, $0xd3bf9238; DATA ·rc+324(SB)/4, $0x225886eb; DATA ·rc+328(SB)/4, $0x6cbab958; DATA ·rc+332(SB)/4, $0xe51071b4
DATA ·rc+336(SB)/4, $0xdb863ce5; DATA ·rc+340(SB)/4, $0xaef0c677; DATA ·rc+344(SB)/4, $0x933dfddd; DATA ·rc+348(SB)/4, $0x24e1128d
DATA ·rc+352(SB)/4, $0xbb606268; DATA ·rc+356(SB)/4, $0xffeba09c; DATA ·rc+360(SB)/4, $0x83e48de3; DATA ·rc+364(SB)/4, $0xcb2212b1
DATA ·rc+368(SB)/4, $0x734bd3dc; DATA ·rc+372(SB)/4, $0xe2e4d19c; DATA ·rc+376(SB)/4, $0x2db91a4e; DATA ·rc+380(SB)/4, $0x23129114

GLOBL ·rc(SB), (NOPTR+RODATA), $384
