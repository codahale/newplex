//go:build amd64 && !purego

#include "textflag.h"

// ROUND_8_STEP: s0..s5 are S-registers, t0, t1 are T-registers, disp is displacement from AX
// Op 1: s0 -> s1
// Op 2: t0 -> s5
// Op 3: s4 -> s3
// Op 4: s2 -> t1
// Interleaves 4 F-functions to utilize AES pipeline.
// Uses X8, X9, X10, X11 for intermediate states.
// Assumes AX points to roundConstants base for this step.
#define ROUND_8_STEP(s0, s1, s2, s3, s4, s5, t0, t1, disp) \
	MOVOU s0, X8; MOVOU t0, X9; MOVOU s4, X10; MOVOU s2, X11; \
	AESENC disp+0(AX), X8; \
	AESENC disp+16(AX), X9; \
	AESENC disp+32(AX), X10; \
	AESENC disp+48(AX), X11; \
	AESENC X15, X8; \
	AESENC X15, X9; \
	AESENC X15, X10; \
	AESENC X15, X11; \
	PXOR X8, s1; \
	PXOR X9, s5; \
	PXOR X10, s3; \
	PXOR X11, t1

// func permute(state *[128]byte)
TEXT ·permute(SB), NOSPLIT, $0
	MOVQ state+0(FP), DI
	
	PXOR X15, X15     // zero
	
	MOVOU 0(DI), X0   // x0
	MOVOU 16(DI), X1  // x1
	MOVOU 32(DI), X2  // x2
	MOVOU 48(DI), X3  // x3
	MOVOU 64(DI), X4  // x4
	MOVOU 80(DI), X5  // x5
	MOVOU 96(DI), X6  // x6
	MOVOU 112(DI), X7 // x7
	
	LEAQ ·roundConstants(SB), AX
	
	// Reg mapping:
	// S: X0, X1, X6, X5, X4, X3
	// T: X2, X7
	
	// Unroll 18 rounds (3 x 6)
	
	// Block 1
	ROUND_8_STEP(X0, X1, X6, X5, X4, X3, X2, X7, 0)
	ROUND_8_STEP(X1, X6, X5, X4, X3, X0, X7, X2, 64)
	ADDQ $128, AX
	ROUND_8_STEP(X6, X5, X4, X3, X0, X1, X2, X7, 0)
	ROUND_8_STEP(X5, X4, X3, X0, X1, X6, X7, X2, 64)
	ADDQ $128, AX
	ROUND_8_STEP(X4, X3, X0, X1, X6, X5, X2, X7, 0)
	ROUND_8_STEP(X3, X0, X1, X6, X5, X4, X7, X2, 64)
	ADDQ $128, AX
	
	// Block 2
	ROUND_8_STEP(X0, X1, X6, X5, X4, X3, X2, X7, 0)
	ROUND_8_STEP(X1, X6, X5, X4, X3, X0, X7, X2, 64)
	ADDQ $128, AX
	ROUND_8_STEP(X6, X5, X4, X3, X0, X1, X2, X7, 0)
	ROUND_8_STEP(X5, X4, X3, X0, X1, X6, X7, X2, 64)
	ADDQ $128, AX
	ROUND_8_STEP(X4, X3, X0, X1, X6, X5, X2, X7, 0)
	ROUND_8_STEP(X3, X0, X1, X6, X5, X4, X7, X2, 64)
	ADDQ $128, AX
	
	// Block 3
	ROUND_8_STEP(X0, X1, X6, X5, X4, X3, X2, X7, 0)
	ROUND_8_STEP(X1, X6, X5, X4, X3, X0, X7, X2, 64)
	ADDQ $128, AX
	ROUND_8_STEP(X6, X5, X4, X3, X0, X1, X2, X7, 0)
	ROUND_8_STEP(X5, X4, X3, X0, X1, X6, X7, X2, 64)
	ADDQ $128, AX
	ROUND_8_STEP(X4, X3, X0, X1, X6, X5, X2, X7, 0)
	ROUND_8_STEP(X3, X0, X1, X6, X5, X4, X7, X2, 64)
	
	MOVOU X0, 0(DI)
	MOVOU X1, 16(DI)
	MOVOU X2, 32(DI)
	MOVOU X3, 48(DI)
	MOVOU X4, 64(DI)
	MOVOU X5, 80(DI)
	MOVOU X6, 96(DI)
	MOVOU X7, 112(DI)
	RET
GLOBL ·roundConstants(SB), (NOPTR+RODATA), $1152
DATA ·roundConstants+0(SB)/4, $0x09
DATA ·roundConstants+4(SB)/4, $0x19
DATA ·roundConstants+8(SB)/4, $0x29
DATA ·roundConstants+12(SB)/4, $0x39
DATA ·roundConstants+16(SB)/4, $0x0a
DATA ·roundConstants+20(SB)/4, $0x1a
DATA ·roundConstants+24(SB)/4, $0x2a
DATA ·roundConstants+28(SB)/4, $0x3a
DATA ·roundConstants+32(SB)/4, $0x0b
DATA ·roundConstants+36(SB)/4, $0x1b
DATA ·roundConstants+40(SB)/4, $0x2b
DATA ·roundConstants+44(SB)/4, $0x3b
DATA ·roundConstants+48(SB)/4, $0x0c
DATA ·roundConstants+52(SB)/4, $0x1c
DATA ·roundConstants+56(SB)/4, $0x2c
DATA ·roundConstants+60(SB)/4, $0x3c
DATA ·roundConstants+64(SB)/4, $0x0d
DATA ·roundConstants+68(SB)/4, $0x1d
DATA ·roundConstants+72(SB)/4, $0x2d
DATA ·roundConstants+76(SB)/4, $0x3d
DATA ·roundConstants+80(SB)/4, $0x0e
DATA ·roundConstants+84(SB)/4, $0x1e
DATA ·roundConstants+88(SB)/4, $0x2e
DATA ·roundConstants+92(SB)/4, $0x3e
DATA ·roundConstants+96(SB)/4, $0x0f
DATA ·roundConstants+100(SB)/4, $0x1f
DATA ·roundConstants+104(SB)/4, $0x2f
DATA ·roundConstants+108(SB)/4, $0x3f
DATA ·roundConstants+112(SB)/4, $0x00
DATA ·roundConstants+116(SB)/4, $0x10
DATA ·roundConstants+120(SB)/4, $0x20
DATA ·roundConstants+124(SB)/4, $0x30
DATA ·roundConstants+128(SB)/4, $0x01
DATA ·roundConstants+132(SB)/4, $0x11
DATA ·roundConstants+136(SB)/4, $0x21
DATA ·roundConstants+140(SB)/4, $0x31
DATA ·roundConstants+144(SB)/4, $0x02
DATA ·roundConstants+148(SB)/4, $0x12
DATA ·roundConstants+152(SB)/4, $0x22
DATA ·roundConstants+156(SB)/4, $0x32
DATA ·roundConstants+160(SB)/4, $0x03
DATA ·roundConstants+164(SB)/4, $0x13
DATA ·roundConstants+168(SB)/4, $0x23
DATA ·roundConstants+172(SB)/4, $0x33
DATA ·roundConstants+176(SB)/4, $0x04
DATA ·roundConstants+180(SB)/4, $0x14
DATA ·roundConstants+184(SB)/4, $0x24
DATA ·roundConstants+188(SB)/4, $0x34
DATA ·roundConstants+192(SB)/4, $0x05
DATA ·roundConstants+196(SB)/4, $0x15
DATA ·roundConstants+200(SB)/4, $0x25
DATA ·roundConstants+204(SB)/4, $0x35
DATA ·roundConstants+208(SB)/4, $0x06
DATA ·roundConstants+212(SB)/4, $0x16
DATA ·roundConstants+216(SB)/4, $0x26
DATA ·roundConstants+220(SB)/4, $0x36
DATA ·roundConstants+224(SB)/4, $0x07
DATA ·roundConstants+228(SB)/4, $0x17
DATA ·roundConstants+232(SB)/4, $0x27
DATA ·roundConstants+236(SB)/4, $0x37
DATA ·roundConstants+240(SB)/4, $0x18
DATA ·roundConstants+244(SB)/4, $0x08
DATA ·roundConstants+248(SB)/4, $0x38
DATA ·roundConstants+252(SB)/4, $0x28
DATA ·roundConstants+256(SB)/4, $0x19
DATA ·roundConstants+260(SB)/4, $0x09
DATA ·roundConstants+264(SB)/4, $0x39
DATA ·roundConstants+268(SB)/4, $0x29
DATA ·roundConstants+272(SB)/4, $0x1a
DATA ·roundConstants+276(SB)/4, $0x0a
DATA ·roundConstants+280(SB)/4, $0x3a
DATA ·roundConstants+284(SB)/4, $0x2a
DATA ·roundConstants+288(SB)/4, $0x1b
DATA ·roundConstants+292(SB)/4, $0x0b
DATA ·roundConstants+296(SB)/4, $0x3b
DATA ·roundConstants+300(SB)/4, $0x2b
DATA ·roundConstants+304(SB)/4, $0x1c
DATA ·roundConstants+308(SB)/4, $0x0c
DATA ·roundConstants+312(SB)/4, $0x3c
DATA ·roundConstants+316(SB)/4, $0x2c
DATA ·roundConstants+320(SB)/4, $0x1d
DATA ·roundConstants+324(SB)/4, $0x0d
DATA ·roundConstants+328(SB)/4, $0x3d
DATA ·roundConstants+332(SB)/4, $0x2d
DATA ·roundConstants+336(SB)/4, $0x1e
DATA ·roundConstants+340(SB)/4, $0x0e
DATA ·roundConstants+344(SB)/4, $0x3e
DATA ·roundConstants+348(SB)/4, $0x2e
DATA ·roundConstants+352(SB)/4, $0x1f
DATA ·roundConstants+356(SB)/4, $0x0f
DATA ·roundConstants+360(SB)/4, $0x3f
DATA ·roundConstants+364(SB)/4, $0x2f
DATA ·roundConstants+368(SB)/4, $0x10
DATA ·roundConstants+372(SB)/4, $0x00
DATA ·roundConstants+376(SB)/4, $0x30
DATA ·roundConstants+380(SB)/4, $0x20
DATA ·roundConstants+384(SB)/4, $0x11
DATA ·roundConstants+388(SB)/4, $0x01
DATA ·roundConstants+392(SB)/4, $0x31
DATA ·roundConstants+396(SB)/4, $0x21
DATA ·roundConstants+400(SB)/4, $0x12
DATA ·roundConstants+404(SB)/4, $0x02
DATA ·roundConstants+408(SB)/4, $0x32
DATA ·roundConstants+412(SB)/4, $0x22
DATA ·roundConstants+416(SB)/4, $0x13
DATA ·roundConstants+420(SB)/4, $0x03
DATA ·roundConstants+424(SB)/4, $0x33
DATA ·roundConstants+428(SB)/4, $0x23
DATA ·roundConstants+432(SB)/4, $0x14
DATA ·roundConstants+436(SB)/4, $0x04
DATA ·roundConstants+440(SB)/4, $0x34
DATA ·roundConstants+444(SB)/4, $0x24
DATA ·roundConstants+448(SB)/4, $0x15
DATA ·roundConstants+452(SB)/4, $0x05
DATA ·roundConstants+456(SB)/4, $0x35
DATA ·roundConstants+460(SB)/4, $0x25
DATA ·roundConstants+464(SB)/4, $0x16
DATA ·roundConstants+468(SB)/4, $0x06
DATA ·roundConstants+472(SB)/4, $0x36
DATA ·roundConstants+476(SB)/4, $0x26
DATA ·roundConstants+480(SB)/4, $0x17
DATA ·roundConstants+484(SB)/4, $0x07
DATA ·roundConstants+488(SB)/4, $0x37
DATA ·roundConstants+492(SB)/4, $0x27
DATA ·roundConstants+496(SB)/4, $0x28
DATA ·roundConstants+500(SB)/4, $0x38
DATA ·roundConstants+504(SB)/4, $0x08
DATA ·roundConstants+508(SB)/4, $0x18
DATA ·roundConstants+512(SB)/4, $0x29
DATA ·roundConstants+516(SB)/4, $0x39
DATA ·roundConstants+520(SB)/4, $0x09
DATA ·roundConstants+524(SB)/4, $0x19
DATA ·roundConstants+528(SB)/4, $0x2a
DATA ·roundConstants+532(SB)/4, $0x3a
DATA ·roundConstants+536(SB)/4, $0x0a
DATA ·roundConstants+540(SB)/4, $0x1a
DATA ·roundConstants+544(SB)/4, $0x2b
DATA ·roundConstants+548(SB)/4, $0x3b
DATA ·roundConstants+552(SB)/4, $0x0b
DATA ·roundConstants+556(SB)/4, $0x1b
DATA ·roundConstants+560(SB)/4, $0x2c
DATA ·roundConstants+564(SB)/4, $0x3c
DATA ·roundConstants+568(SB)/4, $0x0c
DATA ·roundConstants+572(SB)/4, $0x1c
DATA ·roundConstants+576(SB)/4, $0x2d
DATA ·roundConstants+580(SB)/4, $0x3d
DATA ·roundConstants+584(SB)/4, $0x0d
DATA ·roundConstants+588(SB)/4, $0x1d
DATA ·roundConstants+592(SB)/4, $0x2e
DATA ·roundConstants+596(SB)/4, $0x3e
DATA ·roundConstants+600(SB)/4, $0x0e
DATA ·roundConstants+604(SB)/4, $0x1e
DATA ·roundConstants+608(SB)/4, $0x2f
DATA ·roundConstants+612(SB)/4, $0x3f
DATA ·roundConstants+616(SB)/4, $0x0f
DATA ·roundConstants+620(SB)/4, $0x1f
DATA ·roundConstants+624(SB)/4, $0x20
DATA ·roundConstants+628(SB)/4, $0x30
DATA ·roundConstants+632(SB)/4, $0x00
DATA ·roundConstants+636(SB)/4, $0x10
DATA ·roundConstants+640(SB)/4, $0x21
DATA ·roundConstants+644(SB)/4, $0x31
DATA ·roundConstants+648(SB)/4, $0x01
DATA ·roundConstants+652(SB)/4, $0x11
DATA ·roundConstants+656(SB)/4, $0x22
DATA ·roundConstants+660(SB)/4, $0x32
DATA ·roundConstants+664(SB)/4, $0x02
DATA ·roundConstants+668(SB)/4, $0x12
DATA ·roundConstants+672(SB)/4, $0x23
DATA ·roundConstants+676(SB)/4, $0x33
DATA ·roundConstants+680(SB)/4, $0x03
DATA ·roundConstants+684(SB)/4, $0x13
DATA ·roundConstants+688(SB)/4, $0x24
DATA ·roundConstants+692(SB)/4, $0x34
DATA ·roundConstants+696(SB)/4, $0x04
DATA ·roundConstants+700(SB)/4, $0x14
DATA ·roundConstants+704(SB)/4, $0x25
DATA ·roundConstants+708(SB)/4, $0x35
DATA ·roundConstants+712(SB)/4, $0x05
DATA ·roundConstants+716(SB)/4, $0x15
DATA ·roundConstants+720(SB)/4, $0x26
DATA ·roundConstants+724(SB)/4, $0x36
DATA ·roundConstants+728(SB)/4, $0x06
DATA ·roundConstants+732(SB)/4, $0x16
DATA ·roundConstants+736(SB)/4, $0x27
DATA ·roundConstants+740(SB)/4, $0x37
DATA ·roundConstants+744(SB)/4, $0x07
DATA ·roundConstants+748(SB)/4, $0x17
DATA ·roundConstants+752(SB)/4, $0x38
DATA ·roundConstants+756(SB)/4, $0x28
DATA ·roundConstants+760(SB)/4, $0x18
DATA ·roundConstants+764(SB)/4, $0x08
DATA ·roundConstants+768(SB)/4, $0x39
DATA ·roundConstants+772(SB)/4, $0x29
DATA ·roundConstants+776(SB)/4, $0x19
DATA ·roundConstants+780(SB)/4, $0x09
DATA ·roundConstants+784(SB)/4, $0x3a
DATA ·roundConstants+788(SB)/4, $0x2a
DATA ·roundConstants+792(SB)/4, $0x1a
DATA ·roundConstants+796(SB)/4, $0x0a
DATA ·roundConstants+800(SB)/4, $0x3b
DATA ·roundConstants+804(SB)/4, $0x2b
DATA ·roundConstants+808(SB)/4, $0x1b
DATA ·roundConstants+812(SB)/4, $0x0b
DATA ·roundConstants+816(SB)/4, $0x3c
DATA ·roundConstants+820(SB)/4, $0x2c
DATA ·roundConstants+824(SB)/4, $0x1c
DATA ·roundConstants+828(SB)/4, $0x0c
DATA ·roundConstants+832(SB)/4, $0x3d
DATA ·roundConstants+836(SB)/4, $0x2d
DATA ·roundConstants+840(SB)/4, $0x1d
DATA ·roundConstants+844(SB)/4, $0x0d
DATA ·roundConstants+848(SB)/4, $0x3e
DATA ·roundConstants+852(SB)/4, $0x2e
DATA ·roundConstants+856(SB)/4, $0x1e
DATA ·roundConstants+860(SB)/4, $0x0e
DATA ·roundConstants+864(SB)/4, $0x3f
DATA ·roundConstants+868(SB)/4, $0x2f
DATA ·roundConstants+872(SB)/4, $0x1f
DATA ·roundConstants+876(SB)/4, $0x0f
DATA ·roundConstants+880(SB)/4, $0x30
DATA ·roundConstants+884(SB)/4, $0x20
DATA ·roundConstants+888(SB)/4, $0x10
DATA ·roundConstants+892(SB)/4, $0x00
DATA ·roundConstants+896(SB)/4, $0x31
DATA ·roundConstants+900(SB)/4, $0x21
DATA ·roundConstants+904(SB)/4, $0x11
DATA ·roundConstants+908(SB)/4, $0x01
DATA ·roundConstants+912(SB)/4, $0x32
DATA ·roundConstants+916(SB)/4, $0x22
DATA ·roundConstants+920(SB)/4, $0x12
DATA ·roundConstants+924(SB)/4, $0x02
DATA ·roundConstants+928(SB)/4, $0x33
DATA ·roundConstants+932(SB)/4, $0x23
DATA ·roundConstants+936(SB)/4, $0x13
DATA ·roundConstants+940(SB)/4, $0x03
DATA ·roundConstants+944(SB)/4, $0x34
DATA ·roundConstants+948(SB)/4, $0x24
DATA ·roundConstants+952(SB)/4, $0x14
DATA ·roundConstants+956(SB)/4, $0x04
DATA ·roundConstants+960(SB)/4, $0x35
DATA ·roundConstants+964(SB)/4, $0x25
DATA ·roundConstants+968(SB)/4, $0x15
DATA ·roundConstants+972(SB)/4, $0x05
DATA ·roundConstants+976(SB)/4, $0x36
DATA ·roundConstants+980(SB)/4, $0x26
DATA ·roundConstants+984(SB)/4, $0x16
DATA ·roundConstants+988(SB)/4, $0x06
DATA ·roundConstants+992(SB)/4, $0x37
DATA ·roundConstants+996(SB)/4, $0x27
DATA ·roundConstants+1000(SB)/4, $0x17
DATA ·roundConstants+1004(SB)/4, $0x07
DATA ·roundConstants+1008(SB)/4, $0x48
DATA ·roundConstants+1012(SB)/4, $0x58
DATA ·roundConstants+1016(SB)/4, $0x68
DATA ·roundConstants+1020(SB)/4, $0x78
DATA ·roundConstants+1024(SB)/4, $0x49
DATA ·roundConstants+1028(SB)/4, $0x59
DATA ·roundConstants+1032(SB)/4, $0x69
DATA ·roundConstants+1036(SB)/4, $0x79
DATA ·roundConstants+1040(SB)/4, $0x4a
DATA ·roundConstants+1044(SB)/4, $0x5a
DATA ·roundConstants+1048(SB)/4, $0x6a
DATA ·roundConstants+1052(SB)/4, $0x7a
DATA ·roundConstants+1056(SB)/4, $0x4b
DATA ·roundConstants+1060(SB)/4, $0x5b
DATA ·roundConstants+1064(SB)/4, $0x6b
DATA ·roundConstants+1068(SB)/4, $0x7b
DATA ·roundConstants+1072(SB)/4, $0x4c
DATA ·roundConstants+1076(SB)/4, $0x5c
DATA ·roundConstants+1080(SB)/4, $0x6c
DATA ·roundConstants+1084(SB)/4, $0x7c
DATA ·roundConstants+1088(SB)/4, $0x4d
DATA ·roundConstants+1092(SB)/4, $0x5d
DATA ·roundConstants+1096(SB)/4, $0x6d
DATA ·roundConstants+1100(SB)/4, $0x7d
DATA ·roundConstants+1104(SB)/4, $0x4e
DATA ·roundConstants+1108(SB)/4, $0x5e
DATA ·roundConstants+1112(SB)/4, $0x6e
DATA ·roundConstants+1116(SB)/4, $0x7e
DATA ·roundConstants+1120(SB)/4, $0x4f
DATA ·roundConstants+1124(SB)/4, $0x5f
DATA ·roundConstants+1128(SB)/4, $0x6f
DATA ·roundConstants+1132(SB)/4, $0x7f
DATA ·roundConstants+1136(SB)/4, $0x40
DATA ·roundConstants+1140(SB)/4, $0x50
DATA ·roundConstants+1144(SB)/4, $0x60
DATA ·roundConstants+1148(SB)/4, $0x70
