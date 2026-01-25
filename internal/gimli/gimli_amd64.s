//go:build amd64 && !purego

#include "textflag.h"

// func permute(state *[48]byte)
TEXT ·permute(SB), NOSPLIT, $0
	MOVQ state+0(FP), DI

	// Load state into XMM0, XMM1, XMM2
	// Row 0: s[0]..s[3]
	MOVOU 0(DI), X0
	// Row 1: s[4]..s[7]
	MOVOU 16(DI), X1
	// Row 2: s[8]..s[11]
	MOVOU 32(DI), X2

	// Prepare scratch registers
	// X3, X4, X5, X6, X7 available

	// Main loop unrolled 24 times
	// Round 24 (Start)
	
	// SP-box macro
	// Input: X0(x), X1(y), X2(z)
	// Trashes: X3, X4, X5
#define SPBOX() \
	/* x = rotate(x, 24) -> rotate right 8 */ \
	MOVOU X0, X3; \
	PSRLL $8, X0; \
	PSLLL $24, X3; \
	POR X3, X0; \
	\
	/* y = rotate(y, 9) -> rotate left 9 */ \
	MOVOU X1, X3; \
	PSLLL $9, X1; \
	PSRLL $23, X3; \
	POR X3, X1; \
	\
	/* new_x = x ^ (z << 1) ^ ((y&z) << 2) */ \
	MOVOU X2, X3; \
	PSLLL $1, X3; \
	PXOR X0, X3; /* x ^ (z << 1) */ \
	MOVOU X1, X4; \
	PAND X2, X4; /* y & z */ \
	PSLLL $2, X4; \
	PXOR X4, X3; /* new_x stored in X3 */ \
	\
	/* new_y = y ^ x ^ ((x|z) << 1) */ \
	MOVOU X1, X4; \
	PXOR X0, X4; /* y ^ x */ \
	MOVOU X0, X5; \
	POR X2, X5; /* x | z */ \
	PSLLL $1, X5; \
	PXOR X5, X4; /* new_y stored in X4 */ \
	\
	/* new_z = z ^ y ^ ((x&y) << 3) */ \
	MOVOU X2, X5; \
	PXOR X1, X5; /* z ^ y */ \
	MOVOU X0, X6; \
	PAND X1, X6; /* x & y */ \
	PSLLL $3, X6; \
	PXOR X6, X5; /* new_z stored in X5 */ \
	\
	/* Update state */ \
	MOVOU X5, X0; /* new_z becomes next x (s[column] = new_z) according to C code? Wait. */ \
	/* C code:
	   state[8 + column] = new_x; // z <- new_x
	   state[4 + column] = new_y; // y <- new_y
	   state[column]     = new_z; // x <- new_z
	*/ \
	/* My registers: X0=Row0(x), X1=Row1(y), X2=Row2(z) */ \
	/* So: */ \
	MOVOU X3, X2; /* z = new_x */ \
	MOVOU X4, X1; /* y = new_y */ \
	/* X0 is updated last using X5 (new_z) */ \
	MOVOU X5, X0; 

	// Helper for constant addition
	// X0[0] ^= constant
	// Use X7 for constant
#define ADD_CONSTANT(round) \
	MOVL $0x9e377900, R8; \
	XORL $round, R8; \
	MOVQ R8, X7; \
	PXOR X7, X0;

#define SMALL_SWAP() \
	PSHUFD $0xB1, X0, X0

#define BIG_SWAP() \
	PSHUFD $0x4E, X0, X0

	// Round 24
	SPBOX()
	SMALL_SWAP()
	ADD_CONSTANT(24)

	// Round 23
	SPBOX()

	// Round 22
	SPBOX()
	BIG_SWAP()

	// Round 21
	SPBOX()

	// Round 20
	SPBOX()
	SMALL_SWAP()
	ADD_CONSTANT(20)

	// Round 19
	SPBOX()

	// Round 18
	SPBOX()
	BIG_SWAP()

	// Round 17
	SPBOX()

	// Round 16
	SPBOX()
	SMALL_SWAP()
	ADD_CONSTANT(16)

	// Round 15
	SPBOX()

	// Round 14
	SPBOX()
	BIG_SWAP()

	// Round 13
	SPBOX()

	// Round 12
	SPBOX()
	SMALL_SWAP()
	ADD_CONSTANT(12)

	// Round 11
	SPBOX()

	// Round 10
	SPBOX()
	BIG_SWAP()

	// Round 9
	SPBOX()

	// Round 8
	SPBOX()
	SMALL_SWAP()
	ADD_CONSTANT(8)

	// Round 7
	SPBOX()

	// Round 6
	SPBOX()
	BIG_SWAP()

	// Round 5
	SPBOX()

	// Round 4
	SPBOX()
	SMALL_SWAP()
	ADD_CONSTANT(4)

	// Round 3
	SPBOX()

	// Round 2
	SPBOX()
	BIG_SWAP()

	// Round 1
	SPBOX()

	// Store result
	MOVOU X0, 0(DI)
	MOVOU X1, 16(DI)
	MOVOU X2, 32(DI)
	RET
