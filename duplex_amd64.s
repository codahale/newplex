//go:build amd64 && !purego

#include "textflag.h"

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
//   AX = &dst[0]   (ciphertext output)
//   DI = &state[0] (keystream, updated in place)
//   R8 = &src[0]   (plaintext input)
//   CX = n         (bytes remaining)
//   BX, DX         (temporaries)
TEXT ·encryptBlock(SB), NOSPLIT, $0-72
	MOVQ dst_base+0(FP),    AX
	MOVQ state_base+24(FP), DI
	MOVQ src_base+48(FP),   R8
	MOVQ state_len+32(FP),  CX

	// 16-byte SSE2 blocks.
	CMPQ CX, $16
	JB   tail8

loop16:
	MOVOU (DI), X0        // X0 = state[i:i+16]  (keystream block)
	MOVOU (R8), X1        // X1 = src[i:i+16]    (plaintext block)
	PXOR  X1, X0          // X0 = keystream ^ plaintext = ciphertext
	MOVOU X0, (DI)        // state[i:i+16] = ciphertext (update keystream)
	MOVOU X0, (AX)        // dst[i:i+16]   = ciphertext (write output)
	ADDQ  $16, DI
	ADDQ  $16, R8
	ADDQ  $16, AX
	SUBQ  $16, CX
	CMPQ  CX, $16
	JAE   loop16

	// Word-sized tail: handles 0–15 remaining bytes efficiently.
	// Each stage processes the largest aligned unit that fits, then falls through.
tail8:
	CMPQ CX, $8
	JB   tail4
	MOVQ (DI), BX
	MOVQ (R8), DX
	XORQ DX, BX
	MOVQ BX, (DI)
	MOVQ BX, (AX)
	ADDQ $8, DI
	ADDQ $8, R8
	ADDQ $8, AX
	SUBQ $8, CX

tail4:
	CMPQ CX, $4
	JB   tail2
	MOVLQZX (DI), BX
	MOVLQZX (R8), DX
	XORQ    DX, BX
	MOVL    BX, (DI)
	MOVL    BX, (AX)
	ADDQ $4, DI
	ADDQ $4, R8
	ADDQ $4, AX
	SUBQ $4, CX

tail2:
	CMPQ CX, $2
	JB   tail1
	MOVWLZX (DI), BX
	MOVWLZX (R8), DX
	XORL    DX, BX
	MOVW    BX, (DI)
	MOVW    BX, (AX)
	ADDQ $2, DI
	ADDQ $2, R8
	ADDQ $2, AX
	SUBQ $2, CX

tail1:
	TESTQ CX, CX
	JZ    done
	MOVBLZX (DI), BX
	MOVBLZX (R8), DX
	XORL    DX, BX
	MOVB    BX, (DI)
	MOVB    BX, (AX)

done:
	RET
