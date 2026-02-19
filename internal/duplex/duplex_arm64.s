//go:build arm64 && !purego

#include "textflag.h"

// func absorbBlock(state, src []byte)
//
// For each byte i in [0, n): state[i] ^= src[i]
//
// Argument layout (ABI0, 2 × 24-byte slice headers = 48 bytes):
//   state_base+0(FP) state_len+8(FP)  state_cap+16(FP)
//   src_base+24(FP)  src_len+32(FP)   src_cap+40(FP)
//
// Registers:
//   R0 = &state[0]  (read/write; advances with VST1.P)
//   R1 = &src[0]    (read; advances with VLD1.P / MOVD.P / etc.)
//   R2 = n          (bytes remaining)
//   R3, R4          (scalar temporaries)
TEXT ·absorbBlock(SB), NOSPLIT|NOFRAME, $0-48
	MOVD state_base+0(FP), R0
	MOVD src_base+24(FP),  R1
	MOVD state_len+8(FP),  R2

	CMP  $16, R2
	BLT  abs_tail

abs_loop16:
	VLD1   (R0), [V0.B16]          // V0 = state[i:i+16]  (R0 unchanged)
	VLD1.P 16(R1), [V1.B16]        // V1 = src[i:i+16];   R1 += 16
	VEOR   V1.B16, V0.B16, V0.B16  // V0 ^= V1
	VST1.P [V0.B16], 16(R0)        // state[i:i+16] = V0; R0 += 16
	SUBS   $16, R2
	CMP    $16, R2
	BGE    abs_loop16

abs_tail:
	CBZ  R2, abs_done

	TBZ  $3, R2, abs_less_than8
	MOVD   (R0), R3         // load 8 bytes from state
	MOVD.P 8(R1), R4        // load 8 bytes from src; R1 += 8
	EOR    R4, R3, R3       // R3 = state ^ src
	MOVD.P R3, 8(R0)        // store; R0 += 8

abs_less_than8:
	TBZ  $2, R2, abs_less_than4
	MOVWU    (R0), R3       // load 4 bytes from state
	MOVWU.P  4(R1), R4      // load 4 bytes from src; R1 += 4
	EORW     R4, R3, R3     // R3 = state ^ src
	MOVWU.P  R3, 4(R0)      // store; R0 += 4

abs_less_than4:
	TBZ  $1, R2, abs_less_than2
	MOVHU    (R0), R3       // load 2 bytes from state
	MOVHU.P  2(R1), R4      // load 2 bytes from src; R1 += 2
	EORW     R4, R3, R3     // R3 = state ^ src
	MOVHU.P  R3, 2(R0)      // store; R0 += 2

abs_less_than2:
	TBZ    $0, R2, abs_done
	MOVBU  (R0), R3         // load 1 byte from state
	MOVBU  (R1), R4         // load 1 byte from src
	EORW   R4, R3, R3       // R3 = state ^ src
	MOVBU  R3, (R0)         // store

abs_done:
	RET

// func encryptBlock(dst, state, src []byte)
//
// For each byte i in [0, n): state[i] ^= src[i]; dst[i] = state[i]
//
// Argument layout (ABI0, 3 × 24-byte slice headers = 72 bytes):
//   dst_base+0(FP)    dst_len+8(FP)    dst_cap+16(FP)
//   state_base+24(FP) state_len+32(FP) state_cap+40(FP)
//   src_base+48(FP)   src_len+56(FP)   src_cap+64(FP)
//
// Registers:
//   R0 = &dst[0]    (write; advances with VST1.P / MOVD.P / etc.)
//   R1 = &state[0]  (read/write; advances with VST1.P)
//   R2 = &src[0]    (read; advances with VLD1.P / MOVD.P / etc.)
//   R3 = n          (bytes remaining)
//   R4, R5          (scalar temporaries)
TEXT ·encryptBlock(SB), NOSPLIT|NOFRAME, $0-72
	MOVD dst_base+0(FP),    R0
	MOVD state_base+24(FP), R1
	MOVD src_base+48(FP),   R2
	MOVD state_len+32(FP),  R3

	CMP  $16, R3
	BLT  enc_tail

enc_loop16:
	VLD1   (R1), [V0.B16]          // V0 = state[i:i+16] (R1 unchanged)
	VLD1.P 16(R2), [V1.B16]        // V1 = src[i:i+16];   R2 += 16
	VEOR   V1.B16, V0.B16, V0.B16  // V0 = ciphertext = state ^ src
	VST1.P [V0.B16], 16(R1)        // state[i:i+16] = V0; R1 += 16
	VST1.P [V0.B16], 16(R0)        // dst[i:i+16]   = V0; R0 += 16
	SUBS   $16, R3
	CMP    $16, R3
	BGE    enc_loop16

enc_tail:
	CBZ  R3, enc_done

	TBZ  $3, R3, enc_less_than8
	MOVD   (R1), R4         // load 8 bytes from state
	MOVD.P 8(R2), R5        // load 8 bytes from src; R2 += 8
	EOR    R5, R4, R4       // R4 = state ^ src = ciphertext
	MOVD.P R4, 8(R1)        // state = ciphertext; R1 += 8
	MOVD.P R4, 8(R0)        // dst = ciphertext; R0 += 8

enc_less_than8:
	TBZ  $2, R3, enc_less_than4
	MOVWU    (R1), R4       // load 4 bytes from state
	MOVWU.P  4(R2), R5      // load 4 bytes from src; R2 += 4
	EORW     R5, R4, R4     // R4 = state ^ src
	MOVWU.P  R4, 4(R1)      // state = ciphertext; R1 += 4
	MOVWU.P  R4, 4(R0)      // dst = ciphertext; R0 += 4

enc_less_than4:
	TBZ  $1, R3, enc_less_than2
	MOVHU    (R1), R4       // load 2 bytes from state
	MOVHU.P  2(R2), R5      // load 2 bytes from src; R2 += 2
	EORW     R5, R4, R4     // R4 = state ^ src
	MOVHU.P  R4, 2(R1)      // state = ciphertext; R1 += 2
	MOVHU.P  R4, 2(R0)      // dst = ciphertext; R0 += 2

enc_less_than2:
	TBZ  $0, R3, enc_done
	MOVBU  (R1), R4         // load 1 byte from state
	MOVBU  (R2), R5         // load 1 byte from src
	EORW   R5, R4, R4       // R4 = state ^ src
	MOVBU  R4, (R1)         // state = ciphertext
	MOVBU  R4, (R0)         // dst = ciphertext

enc_done:
	RET

// func decryptBlock(plaintext, state, ciphertext []byte)
//
// For each byte i in [0, n): plaintext[i] = state[i] ^ ciphertext[i]; state[i] = ciphertext[i]
//
// Correct even when plaintext and ciphertext alias: ciphertext[i] is loaded
// into a register before plaintext[i] is written, so aliasing is safe.
//
// Argument layout (ABI0, 3 × 24-byte slice headers = 72 bytes):
//   plaintext_base+0(FP)    plaintext_len+8(FP)    plaintext_cap+16(FP)
//   state_base+24(FP)       state_len+32(FP)        state_cap+40(FP)
//   ciphertext_base+48(FP)  ciphertext_len+56(FP)   ciphertext_cap+64(FP)
//
// Registers:
//   R0 = &plaintext[0]   (write; advances with VST1.P / MOVD.P / etc.)
//   R1 = &state[0]       (read/write; non-post-inc read, post-inc write)
//   R2 = &ciphertext[0]  (read; advances with VLD1.P / MOVD.P / etc.)
//   R3 = n               (bytes remaining)
//   R4, R5               (scalar temporaries)
//
// Key NEON property: after VEOR V1, V0, V2 (V2 = V0 ^ V1 = plaintext):
//   V1 (ciphertext) is unchanged and can be written to state.
TEXT ·decryptBlock(SB), NOSPLIT|NOFRAME, $0-72
	MOVD plaintext_base+0(FP),   R0
	MOVD state_base+24(FP),      R1
	MOVD ciphertext_base+48(FP), R2
	MOVD state_len+32(FP),       R3

	CMP  $16, R3
	BLT  dec_tail

dec_loop16:
	VLD1   (R1), [V0.B16]          // V0 = state (keystream); R1 unchanged
	VLD1.P 16(R2), [V1.B16]        // V1 = ciphertext (preserved); R2 += 16
	VEOR   V1.B16, V0.B16, V2.B16  // V2 = plaintext; V1 = ciphertext (unchanged)
	VST1.P [V2.B16], 16(R0)        // plaintext[i:i+16] = V2; R0 += 16
	VST1.P [V1.B16], 16(R1)        // state[i:i+16] = V1; R1 += 16
	SUBS   $16, R3
	CMP    $16, R3
	BGE    dec_loop16

dec_tail:
	CBZ  R3, dec_done

	// Key scalar property: after EOR R5, R4, R4 (R4 = state ^ ciphertext = plaintext):
	// R5 (ciphertext) is unchanged and written to state.
	TBZ  $3, R3, dec_less_than8
	MOVD   (R1), R4         // R4 = state (keystream)
	MOVD.P 8(R2), R5        // R5 = ciphertext; R2 += 8
	EOR    R5, R4, R4       // R4 = plaintext; R5 = ciphertext (unchanged)
	MOVD.P R4, 8(R0)        // plaintext = R4; R0 += 8
	MOVD.P R5, 8(R1)        // state = R5 (ciphertext); R1 += 8

dec_less_than8:
	TBZ  $2, R3, dec_less_than4
	MOVWU    (R1), R4       // R4 = state
	MOVWU.P  4(R2), R5      // R5 = ciphertext; R2 += 4
	EORW     R5, R4, R4     // R4 = plaintext; R5 = ciphertext (unchanged)
	MOVWU.P  R4, 4(R0)      // plaintext = R4; R0 += 4
	MOVWU.P  R5, 4(R1)      // state = R5; R1 += 4

dec_less_than4:
	TBZ  $1, R3, dec_less_than2
	MOVHU    (R1), R4       // R4 = state
	MOVHU.P  2(R2), R5      // R5 = ciphertext; R2 += 2
	EORW     R5, R4, R4     // R4 = plaintext; R5 = ciphertext (unchanged)
	MOVHU.P  R4, 2(R0)      // plaintext = R4; R0 += 2
	MOVHU.P  R5, 2(R1)      // state = R5; R1 += 2

dec_less_than2:
	TBZ  $0, R3, dec_done
	MOVBU  (R1), R4         // R4 = state
	MOVBU  (R2), R5         // R5 = ciphertext
	EORW   R5, R4, R4       // R4 = plaintext; R5 = ciphertext (unchanged)
	MOVBU  R4, (R0)         // plaintext = R4
	MOVBU  R5, (R1)         // state = R5

dec_done:
	RET
