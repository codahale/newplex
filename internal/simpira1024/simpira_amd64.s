//go:build amd64 && !purego

#include "textflag.h"

// ROUND_QUAD performs 4 independent Feistel steps in parallel to leverage AES-NI throughput.
// Each step: dst = AESRound(AESRound(src) ^ roundKey) ^ dst
// Registers X8-X11 hold round keys, X12-X15 are temps.
#define ROUND_QUAD(s0, s1, s2, s3, s4, s5, t0, t1) \
	/* Constant generation for 4 independent F calls */ \
	MOVD AX, X8; PSHUFD $0, X8, X8; PXOR ·constBase(SB), X8; INCL AX; \
	MOVD AX, X9; PSHUFD $0, X9, X9; PXOR ·constBase(SB), X9; INCL AX; \
	MOVD AX, X10; PSHUFD $0, X10, X10; PXOR ·constBase(SB), X10; INCL AX; \
	MOVD AX, X11; PSHUFD $0, X11, X11; PXOR ·constBase(SB), X11; INCL AX; \
	/* Interleaved F calls (4 parallel chains) */ \
	/* First AES round: temp = AESRound(src) ^ roundKey */ \
	MOVAPS s0, X12; \
	MOVAPS t0, X13; \
	MOVAPS s4, X14; \
	MOVAPS s2, X15; \
	AESENC X8, X12; \
	AESENC X9, X13; \
	AESENC X10, X14; \
	AESENC X11, X15; \
	/* Second AES round: temp = AESRound(temp) ^ dst */ \
	AESENC s1, X12; \
	AESENC s5, X13; \
	AESENC s3, X14; \
	AESENC t1, X15; \
	/* Results update: dst = temp */ \
	MOVAPS X12, s1; \
	MOVAPS X13, s5; \
	MOVAPS X14, s3; \
	MOVAPS X15, t1

// func permute(state *[128]byte)
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

	MOVL $1, AX       // c = 1

	// Unroll 18 rounds (3 x 6)
	// Block 1
	ROUND_QUAD(X0, X1, X6, X5, X4, X3, X2, X7) // Round 0
	ROUND_QUAD(X1, X6, X5, X4, X3, X0, X7, X2) // Round 1
	ROUND_QUAD(X6, X5, X4, X3, X0, X1, X2, X7) // Round 2
	ROUND_QUAD(X5, X4, X3, X0, X1, X6, X7, X2) // Round 3
	ROUND_QUAD(X4, X3, X0, X1, X6, X5, X2, X7) // Round 4
	ROUND_QUAD(X3, X0, X1, X6, X5, X4, X7, X2) // Round 5

	// Block 2
	ROUND_QUAD(X0, X1, X6, X5, X4, X3, X2, X7) // Round 6
	ROUND_QUAD(X1, X6, X5, X4, X3, X0, X7, X2) // Round 7
	ROUND_QUAD(X6, X5, X4, X3, X0, X1, X2, X7) // Round 8
	ROUND_QUAD(X5, X4, X3, X0, X1, X6, X7, X2) // Round 9
	ROUND_QUAD(X4, X3, X0, X1, X6, X5, X2, X7) // Round 10
	ROUND_QUAD(X3, X0, X1, X6, X5, X4, X7, X2) // Round 11

	// Block 3
	ROUND_QUAD(X0, X1, X6, X5, X4, X3, X2, X7) // Round 12
	ROUND_QUAD(X1, X6, X5, X4, X3, X0, X7, X2) // Round 13
	ROUND_QUAD(X6, X5, X4, X3, X0, X1, X2, X7) // Round 14
	ROUND_QUAD(X5, X4, X3, X0, X1, X6, X7, X2) // Round 15
	ROUND_QUAD(X4, X3, X0, X1, X6, X5, X2, X7) // Round 16
	ROUND_QUAD(X3, X0, X1, X6, X5, X4, X7, X2) // Round 17

	MOVOU X0, 0(DI)
	MOVOU X1, 16(DI)
	MOVOU X2, 32(DI)
	MOVOU X3, 48(DI)
	MOVOU X4, 64(DI)
	MOVOU X5, 80(DI)
	MOVOU X6, 96(DI)
	MOVOU X7, 112(DI)
	RET

GLOBL ·constBase(SB), (NOPTR+RODATA), $16
DATA ·constBase+0(SB)/4, $0x08
DATA ·constBase+4(SB)/4, $0x18
DATA ·constBase+8(SB)/4, $0x28
DATA ·constBase+12(SB)/4, $0x38
