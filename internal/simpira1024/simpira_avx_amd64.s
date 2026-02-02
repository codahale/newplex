//go:build amd64 && !purego

#include "textflag.h"

// ROUND_8_STEP_AVX: s0..s5 are S-registers, t0, t1 are T-registers, disp is displacement from AX
// Op 1: s0 -> s1
// Op 2: t0 -> s5
// Op 3: s4 -> s3
// Op 4: s2 -> t1
// Interleaves 4 F-functions to utilize AES pipeline.
// Uses X8, X9, X10, X11 for intermediate states.
// Assumes AX points to roundConstants base for this step.
// Uses VEX instructions (VAESENC, VPXOR) to avoid moves and transition penalties.
#define ROUND_8_STEP_AVX(s0, s1, s2, s3, s4, s5, t0, t1, disp) \
	VAESENC disp+0(AX), s0, X8; \
	VAESENC disp+16(AX), t0, X9; \
	VAESENC disp+32(AX), s4, X10; \
	VAESENC disp+48(AX), s2, X11; \
	VAESENC X15, X8, X8; \
	VAESENC X15, X9, X9; \
	VAESENC X15, X10, X10; \
	VAESENC X15, X11, X11; \
	VPXOR X8, s1, s1; \
	VPXOR X9, s5, s5; \
	VPXOR X10, s3, s3; \
	VPXOR X11, t1, t1

// func permuteAVX(state *[128]byte)
TEXT ·permuteAVX(SB), NOSPLIT, $0
	MOVQ state+0(FP), DI
	
	VPXOR X15, X15, X15     // zero
	
	VMOVDQU 0(DI), X0   // x0
	VMOVDQU 16(DI), X1  // x1
	VMOVDQU 32(DI), X2  // x2
	VMOVDQU 48(DI), X3  // x3
	VMOVDQU 64(DI), X4  // x4
	VMOVDQU 80(DI), X5  // x5
	VMOVDQU 96(DI), X6  // x6
	VMOVDQU 112(DI), X7 // x7
	
	LEAQ ·roundConstants(SB), AX
	
	// Reg mapping:
	// S: X0, X1, X6, X5, X4, X3
	// T: X2, X7
	
	// Unroll 18 rounds (3 x 6)
	
	// Block 1
	ROUND_8_STEP_AVX(X0, X1, X6, X5, X4, X3, X2, X7, 0)
	ROUND_8_STEP_AVX(X1, X6, X5, X4, X3, X0, X7, X2, 64)
	ADDQ $128, AX
	ROUND_8_STEP_AVX(X6, X5, X4, X3, X0, X1, X2, X7, 0)
	ROUND_8_STEP_AVX(X5, X4, X3, X0, X1, X6, X7, X2, 64)
	ADDQ $128, AX
	ROUND_8_STEP_AVX(X4, X3, X0, X1, X6, X5, X2, X7, 0)
	ROUND_8_STEP_AVX(X3, X0, X1, X6, X5, X4, X7, X2, 64)
	ADDQ $128, AX
	
	// Block 2
	ROUND_8_STEP_AVX(X0, X1, X6, X5, X4, X3, X2, X7, 0)
	ROUND_8_STEP_AVX(X1, X6, X5, X4, X3, X0, X7, X2, 64)
	ADDQ $128, AX
	ROUND_8_STEP_AVX(X6, X5, X4, X3, X0, X1, X2, X7, 0)
	ROUND_8_STEP_AVX(X5, X4, X3, X0, X1, X6, X7, X2, 64)
	ADDQ $128, AX
	ROUND_8_STEP_AVX(X4, X3, X0, X1, X6, X5, X2, X7, 0)
	ROUND_8_STEP_AVX(X3, X0, X1, X6, X5, X4, X7, X2, 64)
	ADDQ $128, AX
	
	// Block 3
	ROUND_8_STEP_AVX(X0, X1, X6, X5, X4, X3, X2, X7, 0)
	ROUND_8_STEP_AVX(X1, X6, X5, X4, X3, X0, X7, X2, 64)
	ADDQ $128, AX
	ROUND_8_STEP_AVX(X6, X5, X4, X3, X0, X1, X2, X7, 0)
	ROUND_8_STEP_AVX(X5, X4, X3, X0, X1, X6, X7, X2, 64)
	ADDQ $128, AX
	ROUND_8_STEP_AVX(X4, X3, X0, X1, X6, X5, X2, X7, 0)
	ROUND_8_STEP_AVX(X3, X0, X1, X6, X5, X4, X7, X2, 64)
	
	VMOVDQU X0, 0(DI)
	VMOVDQU X1, 16(DI)
	VMOVDQU X2, 32(DI)
	VMOVDQU X3, 48(DI)
	VMOVDQU X4, 64(DI)
	VMOVDQU X5, 80(DI)
	VMOVDQU X6, 96(DI)
	VMOVDQU X7, 112(DI)
	RET
