//go:build amd64 && !purego

#include "textflag.h"

// ROUND_QUAD_SSE performs 4 independent Feistel steps using legacy AESENC (SSE).
// Each step: dst = AESRound(AESRound(src, roundKey), dst)
// Round keys are loaded from fixed offsets k0..k3 relative to SI (base of round key table).
// Uses 2-operand AESENC with explicit MOVAPS copies for source and result.
#define ROUND_QUAD_SSE(s0, s1, s2, s3, s4, s5, t0, t1, k0, k1, k2, k3) \
	MOVOU k0(SI), X8; \
	MOVOU k1(SI), X9; \
	MOVOU k2(SI), X10; \
	MOVOU k3(SI), X11; \
	MOVAPS s0, X12; \
	MOVAPS t0, X13; \
	MOVAPS s4, X14; \
	MOVAPS s2, X15; \
	AESENC X8, X12; \
	AESENC X9, X13; \
	AESENC X10, X14; \
	AESENC X11, X15; \
	AESENC s1, X12; \
	AESENC s5, X13; \
	AESENC s3, X14; \
	AESENC t1, X15; \
	MOVAPS X12, s1; \
	MOVAPS X13, s5; \
	MOVAPS X14, s3; \
	MOVAPS X15, t1

// func permute(state *[128]byte)
TEXT ·permute(SB), NOSPLIT, $0
	MOVQ state+0(FP), DI
	LEAQ ·roundKeys(SB), SI

	MOVOU 0(DI), X0   // x0
	MOVOU 16(DI), X1  // x1
	MOVOU 32(DI), X2  // x2
	MOVOU 48(DI), X3  // x3
	MOVOU 64(DI), X4  // x4
	MOVOU 80(DI), X5  // x5
	MOVOU 96(DI), X6  // x6
	MOVOU 112(DI), X7 // x7

	// Unroll 18 rounds (3 x 6), each round uses 4 keys at offset round*64.
	// Block 1
	ROUND_QUAD_SSE(X0, X1, X6, X5, X4, X3, X2, X7, 0, 16, 32, 48)       // Round 0
	ROUND_QUAD_SSE(X1, X6, X5, X4, X3, X0, X7, X2, 64, 80, 96, 112)     // Round 1
	ROUND_QUAD_SSE(X6, X5, X4, X3, X0, X1, X2, X7, 128, 144, 160, 176)  // Round 2
	ROUND_QUAD_SSE(X5, X4, X3, X0, X1, X6, X7, X2, 192, 208, 224, 240)  // Round 3
	ROUND_QUAD_SSE(X4, X3, X0, X1, X6, X5, X2, X7, 256, 272, 288, 304)  // Round 4
	ROUND_QUAD_SSE(X3, X0, X1, X6, X5, X4, X7, X2, 320, 336, 352, 368)  // Round 5

	// Block 2
	ROUND_QUAD_SSE(X0, X1, X6, X5, X4, X3, X2, X7, 384, 400, 416, 432)  // Round 6
	ROUND_QUAD_SSE(X1, X6, X5, X4, X3, X0, X7, X2, 448, 464, 480, 496)  // Round 7
	ROUND_QUAD_SSE(X6, X5, X4, X3, X0, X1, X2, X7, 512, 528, 544, 560)  // Round 8
	ROUND_QUAD_SSE(X5, X4, X3, X0, X1, X6, X7, X2, 576, 592, 608, 624)  // Round 9
	ROUND_QUAD_SSE(X4, X3, X0, X1, X6, X5, X2, X7, 640, 656, 672, 688)  // Round 10
	ROUND_QUAD_SSE(X3, X0, X1, X6, X5, X4, X7, X2, 704, 720, 736, 752)  // Round 11

	// Block 3
	ROUND_QUAD_SSE(X0, X1, X6, X5, X4, X3, X2, X7, 768, 784, 800, 816)  // Round 12
	ROUND_QUAD_SSE(X1, X6, X5, X4, X3, X0, X7, X2, 832, 848, 864, 880)  // Round 13
	ROUND_QUAD_SSE(X6, X5, X4, X3, X0, X1, X2, X7, 896, 912, 928, 944)  // Round 14
	ROUND_QUAD_SSE(X5, X4, X3, X0, X1, X6, X7, X2, 960, 976, 992, 1008) // Round 15
	ROUND_QUAD_SSE(X4, X3, X0, X1, X6, X5, X2, X7, 1024, 1040, 1056, 1072) // Round 16
	ROUND_QUAD_SSE(X3, X0, X1, X6, X5, X4, X7, X2, 1088, 1104, 1120, 1136) // Round 17

	MOVOU X0, 0(DI)
	MOVOU X1, 16(DI)
	MOVOU X2, 32(DI)
	MOVOU X3, 48(DI)
	MOVOU X4, 64(DI)
	MOVOU X5, 80(DI)
	MOVOU X6, 96(DI)
	MOVOU X7, 112(DI)
	RET

// Precomputed round keys for 18 rounds × 4 F-calls = 72 keys.
// Each key is [c^0x08, c^0x18, c^0x28, c^0x38] for c = 1..72.
GLOBL ·roundKeys(SB), (NOPTR+RODATA), $1152
DATA ·roundKeys+0(SB)/4, $0x09
DATA ·roundKeys+4(SB)/4, $0x19
DATA ·roundKeys+8(SB)/4, $0x29
DATA ·roundKeys+12(SB)/4, $0x39
DATA ·roundKeys+16(SB)/4, $0x0a
DATA ·roundKeys+20(SB)/4, $0x1a
DATA ·roundKeys+24(SB)/4, $0x2a
DATA ·roundKeys+28(SB)/4, $0x3a
DATA ·roundKeys+32(SB)/4, $0x0b
DATA ·roundKeys+36(SB)/4, $0x1b
DATA ·roundKeys+40(SB)/4, $0x2b
DATA ·roundKeys+44(SB)/4, $0x3b
DATA ·roundKeys+48(SB)/4, $0x0c
DATA ·roundKeys+52(SB)/4, $0x1c
DATA ·roundKeys+56(SB)/4, $0x2c
DATA ·roundKeys+60(SB)/4, $0x3c
DATA ·roundKeys+64(SB)/4, $0x0d
DATA ·roundKeys+68(SB)/4, $0x1d
DATA ·roundKeys+72(SB)/4, $0x2d
DATA ·roundKeys+76(SB)/4, $0x3d
DATA ·roundKeys+80(SB)/4, $0x0e
DATA ·roundKeys+84(SB)/4, $0x1e
DATA ·roundKeys+88(SB)/4, $0x2e
DATA ·roundKeys+92(SB)/4, $0x3e
DATA ·roundKeys+96(SB)/4, $0x0f
DATA ·roundKeys+100(SB)/4, $0x1f
DATA ·roundKeys+104(SB)/4, $0x2f
DATA ·roundKeys+108(SB)/4, $0x3f
DATA ·roundKeys+112(SB)/4, $0x00
DATA ·roundKeys+116(SB)/4, $0x10
DATA ·roundKeys+120(SB)/4, $0x20
DATA ·roundKeys+124(SB)/4, $0x30
DATA ·roundKeys+128(SB)/4, $0x01
DATA ·roundKeys+132(SB)/4, $0x11
DATA ·roundKeys+136(SB)/4, $0x21
DATA ·roundKeys+140(SB)/4, $0x31
DATA ·roundKeys+144(SB)/4, $0x02
DATA ·roundKeys+148(SB)/4, $0x12
DATA ·roundKeys+152(SB)/4, $0x22
DATA ·roundKeys+156(SB)/4, $0x32
DATA ·roundKeys+160(SB)/4, $0x03
DATA ·roundKeys+164(SB)/4, $0x13
DATA ·roundKeys+168(SB)/4, $0x23
DATA ·roundKeys+172(SB)/4, $0x33
DATA ·roundKeys+176(SB)/4, $0x04
DATA ·roundKeys+180(SB)/4, $0x14
DATA ·roundKeys+184(SB)/4, $0x24
DATA ·roundKeys+188(SB)/4, $0x34
DATA ·roundKeys+192(SB)/4, $0x05
DATA ·roundKeys+196(SB)/4, $0x15
DATA ·roundKeys+200(SB)/4, $0x25
DATA ·roundKeys+204(SB)/4, $0x35
DATA ·roundKeys+208(SB)/4, $0x06
DATA ·roundKeys+212(SB)/4, $0x16
DATA ·roundKeys+216(SB)/4, $0x26
DATA ·roundKeys+220(SB)/4, $0x36
DATA ·roundKeys+224(SB)/4, $0x07
DATA ·roundKeys+228(SB)/4, $0x17
DATA ·roundKeys+232(SB)/4, $0x27
DATA ·roundKeys+236(SB)/4, $0x37
DATA ·roundKeys+240(SB)/4, $0x18
DATA ·roundKeys+244(SB)/4, $0x08
DATA ·roundKeys+248(SB)/4, $0x38
DATA ·roundKeys+252(SB)/4, $0x28
DATA ·roundKeys+256(SB)/4, $0x19
DATA ·roundKeys+260(SB)/4, $0x09
DATA ·roundKeys+264(SB)/4, $0x39
DATA ·roundKeys+268(SB)/4, $0x29
DATA ·roundKeys+272(SB)/4, $0x1a
DATA ·roundKeys+276(SB)/4, $0x0a
DATA ·roundKeys+280(SB)/4, $0x3a
DATA ·roundKeys+284(SB)/4, $0x2a
DATA ·roundKeys+288(SB)/4, $0x1b
DATA ·roundKeys+292(SB)/4, $0x0b
DATA ·roundKeys+296(SB)/4, $0x3b
DATA ·roundKeys+300(SB)/4, $0x2b
DATA ·roundKeys+304(SB)/4, $0x1c
DATA ·roundKeys+308(SB)/4, $0x0c
DATA ·roundKeys+312(SB)/4, $0x3c
DATA ·roundKeys+316(SB)/4, $0x2c
DATA ·roundKeys+320(SB)/4, $0x1d
DATA ·roundKeys+324(SB)/4, $0x0d
DATA ·roundKeys+328(SB)/4, $0x3d
DATA ·roundKeys+332(SB)/4, $0x2d
DATA ·roundKeys+336(SB)/4, $0x1e
DATA ·roundKeys+340(SB)/4, $0x0e
DATA ·roundKeys+344(SB)/4, $0x3e
DATA ·roundKeys+348(SB)/4, $0x2e
DATA ·roundKeys+352(SB)/4, $0x1f
DATA ·roundKeys+356(SB)/4, $0x0f
DATA ·roundKeys+360(SB)/4, $0x3f
DATA ·roundKeys+364(SB)/4, $0x2f
DATA ·roundKeys+368(SB)/4, $0x10
DATA ·roundKeys+372(SB)/4, $0x00
DATA ·roundKeys+376(SB)/4, $0x30
DATA ·roundKeys+380(SB)/4, $0x20
DATA ·roundKeys+384(SB)/4, $0x11
DATA ·roundKeys+388(SB)/4, $0x01
DATA ·roundKeys+392(SB)/4, $0x31
DATA ·roundKeys+396(SB)/4, $0x21
DATA ·roundKeys+400(SB)/4, $0x12
DATA ·roundKeys+404(SB)/4, $0x02
DATA ·roundKeys+408(SB)/4, $0x32
DATA ·roundKeys+412(SB)/4, $0x22
DATA ·roundKeys+416(SB)/4, $0x13
DATA ·roundKeys+420(SB)/4, $0x03
DATA ·roundKeys+424(SB)/4, $0x33
DATA ·roundKeys+428(SB)/4, $0x23
DATA ·roundKeys+432(SB)/4, $0x14
DATA ·roundKeys+436(SB)/4, $0x04
DATA ·roundKeys+440(SB)/4, $0x34
DATA ·roundKeys+444(SB)/4, $0x24
DATA ·roundKeys+448(SB)/4, $0x15
DATA ·roundKeys+452(SB)/4, $0x05
DATA ·roundKeys+456(SB)/4, $0x35
DATA ·roundKeys+460(SB)/4, $0x25
DATA ·roundKeys+464(SB)/4, $0x16
DATA ·roundKeys+468(SB)/4, $0x06
DATA ·roundKeys+472(SB)/4, $0x36
DATA ·roundKeys+476(SB)/4, $0x26
DATA ·roundKeys+480(SB)/4, $0x17
DATA ·roundKeys+484(SB)/4, $0x07
DATA ·roundKeys+488(SB)/4, $0x37
DATA ·roundKeys+492(SB)/4, $0x27
DATA ·roundKeys+496(SB)/4, $0x28
DATA ·roundKeys+500(SB)/4, $0x38
DATA ·roundKeys+504(SB)/4, $0x08
DATA ·roundKeys+508(SB)/4, $0x18
DATA ·roundKeys+512(SB)/4, $0x29
DATA ·roundKeys+516(SB)/4, $0x39
DATA ·roundKeys+520(SB)/4, $0x09
DATA ·roundKeys+524(SB)/4, $0x19
DATA ·roundKeys+528(SB)/4, $0x2a
DATA ·roundKeys+532(SB)/4, $0x3a
DATA ·roundKeys+536(SB)/4, $0x0a
DATA ·roundKeys+540(SB)/4, $0x1a
DATA ·roundKeys+544(SB)/4, $0x2b
DATA ·roundKeys+548(SB)/4, $0x3b
DATA ·roundKeys+552(SB)/4, $0x0b
DATA ·roundKeys+556(SB)/4, $0x1b
DATA ·roundKeys+560(SB)/4, $0x2c
DATA ·roundKeys+564(SB)/4, $0x3c
DATA ·roundKeys+568(SB)/4, $0x0c
DATA ·roundKeys+572(SB)/4, $0x1c
DATA ·roundKeys+576(SB)/4, $0x2d
DATA ·roundKeys+580(SB)/4, $0x3d
DATA ·roundKeys+584(SB)/4, $0x0d
DATA ·roundKeys+588(SB)/4, $0x1d
DATA ·roundKeys+592(SB)/4, $0x2e
DATA ·roundKeys+596(SB)/4, $0x3e
DATA ·roundKeys+600(SB)/4, $0x0e
DATA ·roundKeys+604(SB)/4, $0x1e
DATA ·roundKeys+608(SB)/4, $0x2f
DATA ·roundKeys+612(SB)/4, $0x3f
DATA ·roundKeys+616(SB)/4, $0x0f
DATA ·roundKeys+620(SB)/4, $0x1f
DATA ·roundKeys+624(SB)/4, $0x20
DATA ·roundKeys+628(SB)/4, $0x30
DATA ·roundKeys+632(SB)/4, $0x00
DATA ·roundKeys+636(SB)/4, $0x10
DATA ·roundKeys+640(SB)/4, $0x21
DATA ·roundKeys+644(SB)/4, $0x31
DATA ·roundKeys+648(SB)/4, $0x01
DATA ·roundKeys+652(SB)/4, $0x11
DATA ·roundKeys+656(SB)/4, $0x22
DATA ·roundKeys+660(SB)/4, $0x32
DATA ·roundKeys+664(SB)/4, $0x02
DATA ·roundKeys+668(SB)/4, $0x12
DATA ·roundKeys+672(SB)/4, $0x23
DATA ·roundKeys+676(SB)/4, $0x33
DATA ·roundKeys+680(SB)/4, $0x03
DATA ·roundKeys+684(SB)/4, $0x13
DATA ·roundKeys+688(SB)/4, $0x24
DATA ·roundKeys+692(SB)/4, $0x34
DATA ·roundKeys+696(SB)/4, $0x04
DATA ·roundKeys+700(SB)/4, $0x14
DATA ·roundKeys+704(SB)/4, $0x25
DATA ·roundKeys+708(SB)/4, $0x35
DATA ·roundKeys+712(SB)/4, $0x05
DATA ·roundKeys+716(SB)/4, $0x15
DATA ·roundKeys+720(SB)/4, $0x26
DATA ·roundKeys+724(SB)/4, $0x36
DATA ·roundKeys+728(SB)/4, $0x06
DATA ·roundKeys+732(SB)/4, $0x16
DATA ·roundKeys+736(SB)/4, $0x27
DATA ·roundKeys+740(SB)/4, $0x37
DATA ·roundKeys+744(SB)/4, $0x07
DATA ·roundKeys+748(SB)/4, $0x17
DATA ·roundKeys+752(SB)/4, $0x38
DATA ·roundKeys+756(SB)/4, $0x28
DATA ·roundKeys+760(SB)/4, $0x18
DATA ·roundKeys+764(SB)/4, $0x08
DATA ·roundKeys+768(SB)/4, $0x39
DATA ·roundKeys+772(SB)/4, $0x29
DATA ·roundKeys+776(SB)/4, $0x19
DATA ·roundKeys+780(SB)/4, $0x09
DATA ·roundKeys+784(SB)/4, $0x3a
DATA ·roundKeys+788(SB)/4, $0x2a
DATA ·roundKeys+792(SB)/4, $0x1a
DATA ·roundKeys+796(SB)/4, $0x0a
DATA ·roundKeys+800(SB)/4, $0x3b
DATA ·roundKeys+804(SB)/4, $0x2b
DATA ·roundKeys+808(SB)/4, $0x1b
DATA ·roundKeys+812(SB)/4, $0x0b
DATA ·roundKeys+816(SB)/4, $0x3c
DATA ·roundKeys+820(SB)/4, $0x2c
DATA ·roundKeys+824(SB)/4, $0x1c
DATA ·roundKeys+828(SB)/4, $0x0c
DATA ·roundKeys+832(SB)/4, $0x3d
DATA ·roundKeys+836(SB)/4, $0x2d
DATA ·roundKeys+840(SB)/4, $0x1d
DATA ·roundKeys+844(SB)/4, $0x0d
DATA ·roundKeys+848(SB)/4, $0x3e
DATA ·roundKeys+852(SB)/4, $0x2e
DATA ·roundKeys+856(SB)/4, $0x1e
DATA ·roundKeys+860(SB)/4, $0x0e
DATA ·roundKeys+864(SB)/4, $0x3f
DATA ·roundKeys+868(SB)/4, $0x2f
DATA ·roundKeys+872(SB)/4, $0x1f
DATA ·roundKeys+876(SB)/4, $0x0f
DATA ·roundKeys+880(SB)/4, $0x30
DATA ·roundKeys+884(SB)/4, $0x20
DATA ·roundKeys+888(SB)/4, $0x10
DATA ·roundKeys+892(SB)/4, $0x00
DATA ·roundKeys+896(SB)/4, $0x31
DATA ·roundKeys+900(SB)/4, $0x21
DATA ·roundKeys+904(SB)/4, $0x11
DATA ·roundKeys+908(SB)/4, $0x01
DATA ·roundKeys+912(SB)/4, $0x32
DATA ·roundKeys+916(SB)/4, $0x22
DATA ·roundKeys+920(SB)/4, $0x12
DATA ·roundKeys+924(SB)/4, $0x02
DATA ·roundKeys+928(SB)/4, $0x33
DATA ·roundKeys+932(SB)/4, $0x23
DATA ·roundKeys+936(SB)/4, $0x13
DATA ·roundKeys+940(SB)/4, $0x03
DATA ·roundKeys+944(SB)/4, $0x34
DATA ·roundKeys+948(SB)/4, $0x24
DATA ·roundKeys+952(SB)/4, $0x14
DATA ·roundKeys+956(SB)/4, $0x04
DATA ·roundKeys+960(SB)/4, $0x35
DATA ·roundKeys+964(SB)/4, $0x25
DATA ·roundKeys+968(SB)/4, $0x15
DATA ·roundKeys+972(SB)/4, $0x05
DATA ·roundKeys+976(SB)/4, $0x36
DATA ·roundKeys+980(SB)/4, $0x26
DATA ·roundKeys+984(SB)/4, $0x16
DATA ·roundKeys+988(SB)/4, $0x06
DATA ·roundKeys+992(SB)/4, $0x37
DATA ·roundKeys+996(SB)/4, $0x27
DATA ·roundKeys+1000(SB)/4, $0x17
DATA ·roundKeys+1004(SB)/4, $0x07
DATA ·roundKeys+1008(SB)/4, $0x48
DATA ·roundKeys+1012(SB)/4, $0x58
DATA ·roundKeys+1016(SB)/4, $0x68
DATA ·roundKeys+1020(SB)/4, $0x78
DATA ·roundKeys+1024(SB)/4, $0x49
DATA ·roundKeys+1028(SB)/4, $0x59
DATA ·roundKeys+1032(SB)/4, $0x69
DATA ·roundKeys+1036(SB)/4, $0x79
DATA ·roundKeys+1040(SB)/4, $0x4a
DATA ·roundKeys+1044(SB)/4, $0x5a
DATA ·roundKeys+1048(SB)/4, $0x6a
DATA ·roundKeys+1052(SB)/4, $0x7a
DATA ·roundKeys+1056(SB)/4, $0x4b
DATA ·roundKeys+1060(SB)/4, $0x5b
DATA ·roundKeys+1064(SB)/4, $0x6b
DATA ·roundKeys+1068(SB)/4, $0x7b
DATA ·roundKeys+1072(SB)/4, $0x4c
DATA ·roundKeys+1076(SB)/4, $0x5c
DATA ·roundKeys+1080(SB)/4, $0x6c
DATA ·roundKeys+1084(SB)/4, $0x7c
DATA ·roundKeys+1088(SB)/4, $0x4d
DATA ·roundKeys+1092(SB)/4, $0x5d
DATA ·roundKeys+1096(SB)/4, $0x6d
DATA ·roundKeys+1100(SB)/4, $0x7d
DATA ·roundKeys+1104(SB)/4, $0x4e
DATA ·roundKeys+1108(SB)/4, $0x5e
DATA ·roundKeys+1112(SB)/4, $0x6e
DATA ·roundKeys+1116(SB)/4, $0x7e
DATA ·roundKeys+1120(SB)/4, $0x4f
DATA ·roundKeys+1124(SB)/4, $0x5f
DATA ·roundKeys+1128(SB)/4, $0x6f
DATA ·roundKeys+1132(SB)/4, $0x7f
DATA ·roundKeys+1136(SB)/4, $0x40
DATA ·roundKeys+1140(SB)/4, $0x50
DATA ·roundKeys+1144(SB)/4, $0x60
DATA ·roundKeys+1148(SB)/4, $0x70
