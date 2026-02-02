//go:build amd64 && !purego

#include "textflag.h"

// func hasAVXAES() bool
TEXT ·hasAVXAES(SB), NOSPLIT, $0
	MOVQ $0, AX
	CPUID
	CMPQ AX, $1
	JL no_avx_aes

	MOVQ $1, AX
	CPUID
	
	// Check AES (Bit 25 of ECX)
	TESTL $(1<<25), CX
	JZ no_avx_aes
	
	// Check AVX (Bit 28 of ECX)
	TESTL $(1<<28), CX
	JZ no_avx_aes
	
	// Check OSXSAVE (Bit 27 of ECX)
	TESTL $(1<<27), CX
	JZ no_avx_aes
	
	// Check XCR0 (OS support for YMM)
	MOVQ $0, CX
	XGETBV
	
	// Check XMM (Bit 1) and YMM (Bit 2) are enabled
	ANDL $6, AX
	CMPL AX, $6
	JNE no_avx_aes
	
	MOVB $1, ret+0(FP)
	RET

no_avx_aes:
	MOVB $0, ret+0(FP)
	RET
