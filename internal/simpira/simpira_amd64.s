// +build amd64,!purego

#include "textflag.h"

// func permute256(state *[32]byte)
TEXT ·permute256(SB), NOSPLIT, $0
	MOVQ state+0(FP), DI
	
	MOVOU 0(DI), X0   // x0
	MOVOU 16(DI), X1  // x1
	
	PXOR X6, X6       // zero
	
	MOVL $1, AX       // c = 1
	MOVL $2, BX       // b = 2
	
	MOVQ $7, CX      // 7 pairs of rounds = 14 rounds
	
loop2_unrolled:
	// Round r (even): x1 ^= F(x0)
	MOVL AX, DX
	XORL BX, DX
	MOVD DX, X4
	PSHUFD $0, X4, X4
	PXOR ·constInc(SB), X4
	MOVOU X0, X5
	AESENC X4, X5
	AESENC X6, X5
	PXOR X5, X1
	INCL AX
	
	// Round r+1 (odd): x0 ^= F(x1)
	MOVL AX, DX
	XORL BX, DX
	MOVD DX, X4
	PSHUFD $0, X4, X4
	PXOR ·constInc(SB), X4
	MOVOU X1, X5
	AESENC X4, X5
	AESENC X6, X5
	PXOR X5, X0
	INCL AX
	
	LOOP loop2_unrolled
	
	// Round 14 (last): x1 ^= F(x0)
	MOVL AX, DX
	XORL BX, DX
	MOVD DX, X4
	PSHUFD $0, X4, X4
	PXOR ·constInc(SB), X4
	MOVOU X0, X5
	AESENC X4, X5
	AESENC X6, X5
	PXOR X5, X1
	
	MOVOU X0, 0(DI)
	MOVOU X1, 16(DI)
	RET

// func permute512(state *[64]byte)
TEXT ·permute512(SB), NOSPLIT, $0
	MOVQ state+0(FP), DI
	
	MOVOU 0(DI), X0   // x0
	MOVOU 16(DI), X1  // x1
	MOVOU 32(DI), X2  // x2
	MOVOU 48(DI), X3  // x3
	
	PXOR X6, X6       // zero
	MOVL $1, AX       // c = 1
	MOVL $4, BX       // b = 4
	
	// Unroll 15 rounds
	
#define ROUND(r0, r1, r2, r3) \
	MOVL AX, DX; \
	XORL BX, DX; \
	MOVD DX, X4; \
	PSHUFD $0, X4, X4; \
	PXOR ·constInc(SB), X4; \
	MOVOU r0, X5; \
	AESENC X4, X5; \
	AESENC X6, X5; \
	PXOR X5, r1; \
	INCL AX; \
	MOVL AX, DX; \
	XORL BX, DX; \
	MOVD DX, X4; \
	PSHUFD $0, X4, X4; \
	PXOR ·constInc(SB), X4; \
	MOVOU r2, X5; \
	AESENC X4, X5; \
	AESENC X6, X5; \
	PXOR X5, r3; \
	INCL AX;

	ROUND(X0, X1, X2, X3) // Round 0
	ROUND(X1, X2, X3, X0) // Round 1
	ROUND(X2, X3, X0, X1) // Round 2
	ROUND(X3, X0, X1, X2) // Round 3
	ROUND(X0, X1, X2, X3) // Round 4
	ROUND(X1, X2, X3, X0) // Round 5
	ROUND(X2, X3, X0, X1) // Round 6
	ROUND(X3, X0, X1, X2) // Round 7
	ROUND(X0, X1, X2, X3) // Round 8
	ROUND(X1, X2, X3, X0) // Round 9
	ROUND(X2, X3, X0, X1) // Round 10
	ROUND(X3, X0, X1, X2) // Round 11
	ROUND(X0, X1, X2, X3) // Round 12
	ROUND(X1, X2, X3, X0) // Round 13
	ROUND(X2, X3, X0, X1) // Round 14

	MOVOU X0, 0(DI)
	MOVOU X1, 16(DI)
	MOVOU X2, 32(DI)
	MOVOU X3, 48(DI)
	RET

// func permute768(state *[96]byte)
TEXT ·permute768(SB), NOSPLIT, $0
	MOVQ state+0(FP), DI
	
	MOVOU 0(DI), X0   // x0
	MOVOU 16(DI), X1  // x1
	MOVOU 32(DI), X2  // x2
	MOVOU 48(DI), X3  // x3
	MOVOU 64(DI), X4  // x4
	MOVOU 80(DI), X5  // x5
	
	PXOR X15, X15     // zero
	MOVL $1, AX       // c = 1
	MOVL $6, BX       // b = 6
	
	// Helper macro for F function
	// Uses X14, X13 as temps. X15 is zero.
	// Updates AX (c).
	// Usage: F_STEP(src, dst)
#define F_STEP(src, dst) \
	MOVL AX, DX; \
	XORL BX, DX; \
	MOVD DX, X14; \
	PSHUFD $0, X14, X14; \
	PXOR ·constInc(SB), X14; \
	MOVOU src, X13; \
	AESENC X14, X13; \
	AESENC X15, X13; \
	PXOR X13, dst; \
	INCL AX

	// ROUND_6_STEP: s0..s5 are registers mapped to s[r]..s[r+5]
	// Op 1: s0 -> s1
	// Op 2: s2 -> s5
	// Op 3: s4 -> s3
#define ROUND_6_STEP(s0, s1, s2, s3, s4, s5) \
	F_STEP(s0, s1); \
	F_STEP(s2, s5); \
	F_STEP(s4, s3)

	// Reg mapping:
	// REG[0]=X0, REG[1]=X1, REG[2]=X2, REG[3]=X5, REG[4]=X4, REG[5]=X3
	
	// Unroll 15 rounds
	ROUND_6_STEP(X0, X1, X2, X5, X4, X3) // Round 0
	ROUND_6_STEP(X1, X2, X5, X4, X3, X0) // Round 1
	ROUND_6_STEP(X2, X5, X4, X3, X0, X1) // Round 2
	ROUND_6_STEP(X5, X4, X3, X0, X1, X2) // Round 3
	ROUND_6_STEP(X4, X3, X0, X1, X2, X5) // Round 4
	ROUND_6_STEP(X3, X0, X1, X2, X5, X4) // Round 5
	
	ROUND_6_STEP(X0, X1, X2, X5, X4, X3) // Round 6
	ROUND_6_STEP(X1, X2, X5, X4, X3, X0) // Round 7
	ROUND_6_STEP(X2, X5, X4, X3, X0, X1) // Round 8
	ROUND_6_STEP(X5, X4, X3, X0, X1, X2) // Round 9
	ROUND_6_STEP(X4, X3, X0, X1, X2, X5) // Round 10
	ROUND_6_STEP(X3, X0, X1, X2, X5, X4) // Round 11
	
	ROUND_6_STEP(X0, X1, X2, X5, X4, X3) // Round 12
	ROUND_6_STEP(X1, X2, X5, X4, X3, X0) // Round 13
	ROUND_6_STEP(X2, X5, X4, X3, X0, X1) // Round 14
	
	MOVOU X0, 0(DI)
	MOVOU X1, 16(DI)
	MOVOU X2, 32(DI)
	MOVOU X3, 48(DI)
	MOVOU X4, 64(DI)
	MOVOU X5, 80(DI)
	RET

// func permute1024(state *[128]byte)
TEXT ·permute1024(SB), NOSPLIT, $0
	MOVQ state+0(FP), DI
	
	MOVOU 0(DI), X0   // x0
	MOVOU 16(DI), X1  // x1
	MOVOU 32(DI), X2  // x2
	MOVOU 48(DI), X3  // x3
	MOVOU 64(DI), X4  // x4
	MOVOU 80(DI), X5  // x5
	MOVOU 96(DI), X6  // x6
	MOVOU 112(DI), X7 // x7
	
	PXOR X15, X15     // zero
	MOVL $1, AX       // c = 1
	MOVL $8, BX       // b = 8
	
	// ROUND_8_STEP: s0..s5 are S-registers, t0, t1 are T-registers
	// Op 1: s0 -> s1
	// Op 2: t0 -> s5
	// Op 3: s4 -> s3
	// Op 4: s2 -> t1
#define ROUND_8_STEP(s0, s1, s2, s3, s4, s5, t0, t1) \
	F_STEP(s0, s1); \
	F_STEP(t0, s5); \
	F_STEP(s4, s3); \
	F_STEP(s2, t1)

	// Reg mapping:
	// S: X0, X1, X6, X5, X4, X3
	// T: X2, X7
	
	// Unroll 18 rounds (3 x 6)
	
	// Block 1
	ROUND_8_STEP(X0, X1, X6, X5, X4, X3, X2, X7) // Round 0
	ROUND_8_STEP(X1, X6, X5, X4, X3, X0, X7, X2) // Round 1
	ROUND_8_STEP(X6, X5, X4, X3, X0, X1, X2, X7) // Round 2
	ROUND_8_STEP(X5, X4, X3, X0, X1, X6, X7, X2) // Round 3
	ROUND_8_STEP(X4, X3, X0, X1, X6, X5, X2, X7) // Round 4
	ROUND_8_STEP(X3, X0, X1, X6, X5, X4, X7, X2) // Round 5
	
	// Block 2
	ROUND_8_STEP(X0, X1, X6, X5, X4, X3, X2, X7) // Round 6
	ROUND_8_STEP(X1, X6, X5, X4, X3, X0, X7, X2) // Round 7
	ROUND_8_STEP(X6, X5, X4, X3, X0, X1, X2, X7) // Round 8
	ROUND_8_STEP(X5, X4, X3, X0, X1, X6, X7, X2) // Round 9
	ROUND_8_STEP(X4, X3, X0, X1, X6, X5, X2, X7) // Round 10
	ROUND_8_STEP(X3, X0, X1, X6, X5, X4, X7, X2) // Round 11
	
	// Block 3
	ROUND_8_STEP(X0, X1, X6, X5, X4, X3, X2, X7) // Round 12
	ROUND_8_STEP(X1, X6, X5, X4, X3, X0, X7, X2) // Round 13
	ROUND_8_STEP(X6, X5, X4, X3, X0, X1, X2, X7) // Round 14
	ROUND_8_STEP(X5, X4, X3, X0, X1, X6, X7, X2) // Round 15
	ROUND_8_STEP(X4, X3, X0, X1, X6, X5, X2, X7) // Round 16
	ROUND_8_STEP(X3, X0, X1, X6, X5, X4, X7, X2) // Round 17
	
	MOVOU X0, 0(DI)
	MOVOU X1, 16(DI)
	MOVOU X2, 32(DI)
	MOVOU X3, 48(DI)
	MOVOU X4, 64(DI)
	MOVOU X5, 80(DI)
	MOVOU X6, 96(DI)
	MOVOU X7, 112(DI)
	RET

// func permute1536(state *[192]byte)
TEXT ·permute1536(SB), NOSPLIT, $0
	MOVQ state+0(FP), DI

	MOVOU 0(DI), X0
	MOVOU 16(DI), X1
	MOVOU 32(DI), X2
	MOVOU 48(DI), X3
	MOVOU 64(DI), X4
	MOVOU 80(DI), X5
	MOVOU 96(DI), X6
	MOVOU 112(DI), X7
	MOVOU 128(DI), X8
	MOVOU 144(DI), X9
	MOVOU 160(DI), X10
	MOVOU 176(DI), X11

	PXOR X15, X15     // zero
	MOVL $1, AX       // c = 1
	MOVL $12, BX      // b = 12

	// ROUND_12_STEP: s0..s9 are S-registers, t0, t1 are T-registers
#define ROUND_12_STEP(s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, t0, t1) \
	F_STEP(s0, s1); \
	F_STEP(t0, s9); \
	F_STEP(s8, s7); \
	F_STEP(s6, s5); \
	F_STEP(s4, s3); \
	F_STEP(s2, t1)

	// Reg mapping:
	// S: X0, X1, X10, X9, X8, X7, X6, X5, X4, X3
	// T: X2, X11

	// Unroll 24 rounds
	// We need 24 rounds, which is 2.4 * 10... let's just do it in a loop or unroll 10 rounds.
	// Since 24 is not a multiple of 10, let's unroll 24 rounds manually or use a loop.
	// Manual unroll is safer for performance and register mapping.

#define ROUNDS_12_10(s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, t0, t1) \
	ROUND_12_STEP(s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, t0, t1) \
	ROUND_12_STEP(s1, s2, s3, s4, s5, s6, s7, s8, s9, s0, t1, t0) \
	ROUND_12_STEP(s2, s3, s4, s5, s6, s7, s8, s9, s0, s1, t0, t1) \
	ROUND_12_STEP(s3, s4, s5, s6, s7, s8, s9, s0, s1, s2, t1, t0) \
	ROUND_12_STEP(s4, s5, s6, s7, s8, s9, s0, s1, s2, s3, t0, t1) \
	ROUND_12_STEP(s5, s6, s7, s8, s9, s0, s1, s2, s3, s4, t1, t0) \
	ROUND_12_STEP(s6, s7, s8, s9, s0, s1, s2, s3, s4, s5, t0, t1) \
	ROUND_12_STEP(s7, s8, s9, s0, s1, s2, s3, s4, s5, s6, t1, t0) \
	ROUND_12_STEP(s8, s9, s0, s1, s2, s3, s4, s5, s6, s7, t0, t1) \
	ROUND_12_STEP(s9, s0, s1, s2, s3, s4, s5, s6, s7, s8, t1, t0)

	ROUNDS_12_10(X0, X1, X10, X9, X8, X7, X6, X5, X4, X3, X2, X11) // Rounds 0-9
	ROUNDS_12_10(X0, X1, X10, X9, X8, X7, X6, X5, X4, X3, X2, X11) // Rounds 10-19
	ROUND_12_STEP(X0, X1, X10, X9, X8, X7, X6, X5, X4, X3, X2, X11) // Round 20
	ROUND_12_STEP(X1, X10, X9, X8, X7, X6, X5, X4, X3, X0, X11, X2) // Round 21
	ROUND_12_STEP(X10, X9, X8, X7, X6, X5, X4, X3, X0, X1, X2, X11) // Round 22
	ROUND_12_STEP(X9, X8, X7, X6, X5, X4, X3, X0, X1, X10, X11, X2) // Round 23

	MOVOU X0, 0(DI)
	MOVOU X1, 16(DI)
	MOVOU X2, 32(DI)
	MOVOU X3, 48(DI)
	MOVOU X4, 64(DI)
	MOVOU X5, 80(DI)
	MOVOU X6, 96(DI)
	MOVOU X7, 112(DI)
	MOVOU X8, 128(DI)
	MOVOU X9, 144(DI)
	MOVOU X10, 160(DI)
	MOVOU X11, 176(DI)
	RET

GLOBL ·constInc(SB), (NOPTR+RODATA), $16
DATA ·constInc+0(SB)/4, $0x00
DATA ·constInc+4(SB)/4, $0x10
DATA ·constInc+8(SB)/4, $0x20
DATA ·constInc+12(SB)/4, $0x30
