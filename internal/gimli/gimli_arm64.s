//go:build arm64 && !purego

#include "textflag.h"

// func permute(state *[48]byte)
TEXT ·permute(SB), NOSPLIT, $0
	MOVD state+0(FP), R0

	// Load state
	// Row 0: s[0]..s[3] -> V0
	VLD1 (R0), [V0.B16]
	ADD $16, R0, R1
	// Row 1: s[4]..s[7] -> V1
	VLD1 (R1), [V1.B16]
	ADD $16, R1, R1
	// Row 2: s[8]..s[11] -> V2
	VLD1 (R1), [V2.B16]

	// Scratch: V3, V4, V5, V6

#define SPBOX() \
	/* x = rotate(x, 24) */ \
	VUSHR $8, V0.S4, V3.S4; \
	VSHL $24, V0.S4, V4.S4; \
	VORR V4.B16, V3.B16, V0.B16; \
	\
	/* y = rotate(y, 9) */ \
	VSHL $9, V1.S4, V3.S4; \
	VUSHR $23, V1.S4, V4.S4; \
	VORR V4.B16, V3.B16, V1.B16; \
	\
	/* new_x = x ^ (z << 1) ^ ((y&z) << 2) */ \
	VSHL $1, V2.S4, V3.S4; \
	VEOR V0.B16, V3.B16, V3.B16; /* x ^ (z<<1) */ \
	VAND V2.B16, V1.B16, V4.B16; /* y & z */ \
	VSHL $2, V4.S4, V4.S4; \
	VEOR V4.B16, V3.B16, V3.B16; /* new_x stored in V3 */ \
	\
	/* new_y = y ^ x ^ ((x|z) << 1) */ \
	VEOR V0.B16, V1.B16, V4.B16; /* y ^ x */ \
	VORR V2.B16, V0.B16, V5.B16; /* x | z */ \
	VSHL $1, V5.S4, V5.S4; \
	VEOR V5.B16, V4.B16, V4.B16; /* new_y stored in V4 */ \
	\
	/* new_z = z ^ y ^ ((x&y) << 3) */ \
	VEOR V1.B16, V2.B16, V5.B16; /* z ^ y */ \
	VAND V1.B16, V0.B16, V6.B16; /* x & y */ \
	VSHL $3, V6.S4, V6.S4; \
	VEOR V6.B16, V5.B16, V5.B16; /* new_z stored in V5 */ \
	\
	/* Update state: x(V0)<-new_z(V5), y(V1)<-new_y(V4), z(V2)<-new_x(V3) */ \
	VORR V5.B16, V5.B16, V0.B16; \
	VORR V4.B16, V4.B16, V1.B16; \
	VORR V3.B16, V3.B16, V2.B16;

#define ADD_CONSTANT(round) \
	MOVD $0x9e377900, R2; \
	MOVD $round, R3; \
	EOR R3, R2, R2; \
	VEOR V6.B16, V6.B16, V6.B16; /* Clear V6 */ \
	VMOV R2, V6.S[0]; \
	VEOR V6.B16, V0.B16, V0.B16;

#define SMALL_SWAP() \
	VREV64 V0.S4, V0.S4

#define BIG_SWAP() \
	VEXT $8, V0.B16, V0.B16, V0.B16

	// Unroll 24 rounds
	SPBOX()
	SMALL_SWAP()
	ADD_CONSTANT(24)

	SPBOX()

	SPBOX()
	BIG_SWAP()

	SPBOX()

	SPBOX()
	SMALL_SWAP()
	ADD_CONSTANT(20)

	SPBOX()

	SPBOX()
	BIG_SWAP()

	SPBOX()

	SPBOX()
	SMALL_SWAP()
	ADD_CONSTANT(16)

	SPBOX()

	SPBOX()
	BIG_SWAP()

	SPBOX()

	SPBOX()
	SMALL_SWAP()
	ADD_CONSTANT(12)

	SPBOX()

	SPBOX()
	BIG_SWAP()

	SPBOX()

	SPBOX()
	SMALL_SWAP()
	ADD_CONSTANT(8)

	SPBOX()

	SPBOX()
	BIG_SWAP()

	SPBOX()

	SPBOX()
	SMALL_SWAP()
	ADD_CONSTANT(4)

	SPBOX()

	SPBOX()
	BIG_SWAP()

	SPBOX()

	// Store result
	VST1 [V0.B16], (R0)
	ADD $16, R0, R1
	VST1 [V1.B16], (R1)
	ADD $16, R1, R1
	VST1 [V2.B16], (R1)
	RET
