//go:build amd64 && !purego

#include "textflag.h"

// func permute(state *[Width]byte)
TEXT ·permute(SB), NOSPLIT, $0
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

GLOBL ·constInc(SB), (NOPTR+RODATA), $16
DATA ·constInc+0(SB)/4, $0x00
DATA ·constInc+4(SB)/4, $0x10
DATA ·constInc+8(SB)/4, $0x20
DATA ·constInc+12(SB)/4, $0x30
