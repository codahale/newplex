//go:build arm64 && !purego

#include "textflag.h"

// func permute(state *[Width]byte)
TEXT ·permute(SB), NOSPLIT, $0
	MOVD state+0(FP), R0
	
	VLD1 (R0), [V0.B16]
	ADD $16, R0, R3
	VLD1 (R3), [V1.B16]
	ADD $16, R3, R3
	VLD1 (R3), [V2.B16]
	ADD $16, R3, R3
	VLD1 (R3), [V3.B16]
	ADD $16, R3, R3
	VLD1 (R3), [V4.B16]
	ADD $16, R3, R3
	VLD1 (R3), [V5.B16]
	ADD $16, R3, R3
	VLD1 (R3), [V6.B16]
	ADD $16, R3, R3
	VLD1 (R3), [V7.B16]
	
	VEOR V16.B16, V16.B16, V16.B16
	VEOR V17.B16, V17.B16, V17.B16
	MOVW $1, R1 // c
	MOVW $8, R2 // b
	
	MOVD $0x10, R3
	VMOV R3, V17.S[1]
	MOVD $0x20, R3
	VMOV R3, V17.S[2]
	MOVD $0x30, R3
	VMOV R3, V17.S[3]

#define F_STEP(s, d) \
    EOR R1, R2, R4; \
    VMOV R4, V18.S4; \
    VEOR V17.B16, V18.B16, V18.B16; \
    VORR s.B16, s.B16, V19.B16; \
    AESE V16.B16, V19.B16; \
    AESMC V19.B16, V19.B16; \
    VEOR V18.B16, V19.B16, V19.B16; \
    AESE V16.B16, V19.B16; \
    AESMC V19.B16, V19.B16; \
    VEOR V19.B16, d.B16, d.B16; \
    ADD $1, R1

#define ROUND_8_STEP(s0, s1, s2, s3, s4, s5, t0, t1) \
	F_STEP(s0, s1); \
	F_STEP(t0, s5); \
	F_STEP(s4, s3); \
	F_STEP(s2, t1)

	// Block 1
	ROUND_8_STEP(V0, V1, V6, V5, V4, V3, V2, V7) // Round 0
	ROUND_8_STEP(V1, V6, V5, V4, V3, V0, V7, V2) // Round 1
	ROUND_8_STEP(V6, V5, V4, V3, V0, V1, V2, V7) // Round 2
	ROUND_8_STEP(V5, V4, V3, V0, V1, V6, V7, V2) // Round 3
	ROUND_8_STEP(V4, V3, V0, V1, V6, V5, V2, V7) // Round 4
	ROUND_8_STEP(V3, V0, V1, V6, V5, V4, V7, V2) // Round 5

	// Block 2
	ROUND_8_STEP(V0, V1, V6, V5, V4, V3, V2, V7) // Round 6
	ROUND_8_STEP(V1, V6, V5, V4, V3, V0, V7, V2) // Round 7
	ROUND_8_STEP(V6, V5, V4, V3, V0, V1, V2, V7) // Round 8
	ROUND_8_STEP(V5, V4, V3, V0, V1, V6, V7, V2) // Round 9
	ROUND_8_STEP(V4, V3, V0, V1, V6, V5, V2, V7) // Round 10
	ROUND_8_STEP(V3, V0, V1, V6, V5, V4, V7, V2) // Round 11

	// Block 3
	ROUND_8_STEP(V0, V1, V6, V5, V4, V3, V2, V7) // Round 12
	ROUND_8_STEP(V1, V6, V5, V4, V3, V0, V7, V2) // Round 13
	ROUND_8_STEP(V6, V5, V4, V3, V0, V1, V2, V7) // Round 14
	ROUND_8_STEP(V5, V4, V3, V0, V1, V6, V7, V2) // Round 15
	ROUND_8_STEP(V4, V3, V0, V1, V6, V5, V2, V7) // Round 16
	ROUND_8_STEP(V3, V0, V1, V6, V5, V4, V7, V2) // Round 17

	MOVD state+0(FP), R0
	VST1 [V0.B16], (R0)
	ADD $16, R0, R3
	VST1 [V1.B16], (R3)
	ADD $16, R3, R3
	VST1 [V2.B16], (R3)
	ADD $16, R3, R3
	VST1 [V3.B16], (R3)
	ADD $16, R3, R3
	VST1 [V4.B16], (R3)
	ADD $16, R3, R3
	VST1 [V5.B16], (R3)
	ADD $16, R3, R3
	VST1 [V6.B16], (R3)
	ADD $16, R3, R3
	VST1 [V7.B16], (R3)
	RET
