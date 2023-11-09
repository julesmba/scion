// This file is mostly a copy of the file of the same name in the crypto/aes go package
// The key expansion for the decryption keys has been removed in this file

// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// func encryptBlockAsm(nr int, xk *uint32, dst, src *byte)
TEXT ·encryptBlockAsm(SB),NOSPLIT,$0
	MOVQ nr+0(FP), CX
	MOVQ xk+8(FP), AX
	MOVQ dst+16(FP), DX
	MOVQ src+24(FP), BX
	MOVUPS 0(AX), X1
	MOVUPS 0(BX), X0
	ADDQ $16, AX
	PXOR X1, X0
	SUBQ $12, CX
	JE Lenc192
	JB Lenc128
Lenc256:
	MOVUPS 0(AX), X1
	AESENC X1, X0
	MOVUPS 16(AX), X1
	AESENC X1, X0
	ADDQ $32, AX
Lenc192:
	MOVUPS 0(AX), X1
	AESENC X1, X0
	MOVUPS 16(AX), X1
	AESENC X1, X0
	ADDQ $32, AX
Lenc128:
	MOVUPS 0(AX), X1
	AESENC X1, X0
	MOVUPS 16(AX), X1
	AESENC X1, X0
	MOVUPS 32(AX), X1
	AESENC X1, X0
	MOVUPS 48(AX), X1
	AESENC X1, X0
	MOVUPS 64(AX), X1
	AESENC X1, X0
	MOVUPS 80(AX), X1
	AESENC X1, X0
	MOVUPS 96(AX), X1
	AESENC X1, X0
	MOVUPS 112(AX), X1
	AESENC X1, X0
	MOVUPS 128(AX), X1
	AESENC X1, X0
	MOVUPS 144(AX), X1
	AESENCLAST X1, X0
	MOVUPS X0, 0(DX)
	RET

// func decryptBlockAsm(nr int, xk *uint32, dst, src *byte)
TEXT ·decryptBlockAsm(SB),NOSPLIT,$0
	MOVQ nr+0(FP), CX
	MOVQ xk+8(FP), AX
	MOVQ dst+16(FP), DX
	MOVQ src+24(FP), BX
	MOVUPS 0(AX), X1
	MOVUPS 0(BX), X0
	ADDQ $16, AX
	PXOR X1, X0
	SUBQ $12, CX
	JE Ldec192
	JB Ldec128
Ldec256:
	MOVUPS 0(AX), X1
	AESDEC X1, X0
	MOVUPS 16(AX), X1
	AESDEC X1, X0
	ADDQ $32, AX
Ldec192:
	MOVUPS 0(AX), X1
	AESDEC X1, X0
	MOVUPS 16(AX), X1
	AESDEC X1, X0
	ADDQ $32, AX
Ldec128:
	MOVUPS 0(AX), X1
	AESDEC X1, X0
	MOVUPS 16(AX), X1
	AESDEC X1, X0
	MOVUPS 32(AX), X1
	AESDEC X1, X0
	MOVUPS 48(AX), X1
	AESDEC X1, X0
	MOVUPS 64(AX), X1
	AESDEC X1, X0
	MOVUPS 80(AX), X1
	AESDEC X1, X0
	MOVUPS 96(AX), X1
	AESDEC X1, X0
	MOVUPS 112(AX), X1
	AESDEC X1, X0
	MOVUPS 128(AX), X1
	AESDEC X1, X0
	MOVUPS 144(AX), X1
	AESDECLAST X1, X0
	MOVUPS X0, 0(DX)
	RET

// func expandKeyAsm(nr int, key *byte, enc) {
// Note that round keys are stored in uint128 format, not uint32
TEXT ·expandKeyAsm(SB),NOSPLIT,$0
	MOVQ nr+0(FP), CX
	MOVQ key+8(FP), AX
	MOVQ enc+16(FP), BX
	MOVUPS (AX), X0
	// enc
	MOVUPS X0, (BX)
	ADDQ $16, BX
	PXOR X4, X4 // _expand_key_* expect X4 to be zero
	CMPL CX, $12
	JE Lexp_enc192
	JB Lexp_enc128
Lexp_enc256:
	MOVUPS 16(AX), X2
	MOVUPS X2, (BX)
	ADDQ $16, BX
	AESKEYGENASSIST $0x01, X2, X1
	CALL _expand_key_256a<>(SB)
	AESKEYGENASSIST $0x01, X0, X1
	CALL _expand_key_256b<>(SB)
	AESKEYGENASSIST $0x02, X2, X1
	CALL _expand_key_256a<>(SB)
	AESKEYGENASSIST $0x02, X0, X1
	CALL _expand_key_256b<>(SB)
	AESKEYGENASSIST $0x04, X2, X1
	CALL _expand_key_256a<>(SB)
	AESKEYGENASSIST $0x04, X0, X1
	CALL _expand_key_256b<>(SB)
	AESKEYGENASSIST $0x08, X2, X1
	CALL _expand_key_256a<>(SB)
	AESKEYGENASSIST $0x08, X0, X1
	CALL _expand_key_256b<>(SB)
	AESKEYGENASSIST $0x10, X2, X1
	CALL _expand_key_256a<>(SB)
	AESKEYGENASSIST $0x10, X0, X1
	CALL _expand_key_256b<>(SB)
	AESKEYGENASSIST $0x20, X2, X1
	CALL _expand_key_256a<>(SB)
	AESKEYGENASSIST $0x20, X0, X1
	CALL _expand_key_256b<>(SB)
	AESKEYGENASSIST $0x40, X2, X1
	CALL _expand_key_256a<>(SB)
	RET
Lexp_enc192:
	MOVQ 16(AX), X2
	AESKEYGENASSIST $0x01, X2, X1
	CALL _expand_key_192a<>(SB)
	AESKEYGENASSIST $0x02, X2, X1
	CALL _expand_key_192b<>(SB)
	AESKEYGENASSIST $0x04, X2, X1
	CALL _expand_key_192a<>(SB)
	AESKEYGENASSIST $0x08, X2, X1
	CALL _expand_key_192b<>(SB)
	AESKEYGENASSIST $0x10, X2, X1
	CALL _expand_key_192a<>(SB)
	AESKEYGENASSIST $0x20, X2, X1
	CALL _expand_key_192b<>(SB)
	AESKEYGENASSIST $0x40, X2, X1
	CALL _expand_key_192a<>(SB)
	AESKEYGENASSIST $0x80, X2, X1
	CALL _expand_key_192b<>(SB)
	RET
Lexp_enc128:
	AESKEYGENASSIST $0x01, X0, X1
	CALL _expand_key_128<>(SB)
	AESKEYGENASSIST $0x02, X0, X1
	CALL _expand_key_128<>(SB)
	AESKEYGENASSIST $0x04, X0, X1
	CALL _expand_key_128<>(SB)
	AESKEYGENASSIST $0x08, X0, X1
	CALL _expand_key_128<>(SB)
	AESKEYGENASSIST $0x10, X0, X1
	CALL _expand_key_128<>(SB)
	AESKEYGENASSIST $0x20, X0, X1
	CALL _expand_key_128<>(SB)
	AESKEYGENASSIST $0x40, X0, X1
	CALL _expand_key_128<>(SB)
	AESKEYGENASSIST $0x80, X0, X1
	CALL _expand_key_128<>(SB)
	AESKEYGENASSIST $0x1b, X0, X1
	CALL _expand_key_128<>(SB)
	AESKEYGENASSIST $0x36, X0, X1
	CALL _expand_key_128<>(SB)
	RET

TEXT _expand_key_128<>(SB),NOSPLIT,$0
	PSHUFD $0xff, X1, X1
	SHUFPS $0x10, X0, X4
	PXOR X4, X0
	SHUFPS $0x8c, X0, X4
	PXOR X4, X0
	PXOR X1, X0
	MOVUPS X0, (BX)
	ADDQ $16, BX
	RET

TEXT _expand_key_192a<>(SB),NOSPLIT,$0
	PSHUFD $0x55, X1, X1
	SHUFPS $0x10, X0, X4
	PXOR X4, X0
	SHUFPS $0x8c, X0, X4
	PXOR X4, X0
	PXOR X1, X0

	MOVAPS X2, X5
	MOVAPS X2, X6
	PSLLDQ $0x4, X5
	PSHUFD $0xff, X0, X3
	PXOR X3, X2
	PXOR X5, X2

	MOVAPS X0, X1
	SHUFPS $0x44, X0, X6
	MOVUPS X6, (BX)
	SHUFPS $0x4e, X2, X1
	MOVUPS X1, 16(BX)
	ADDQ $32, BX
	RET

TEXT _expand_key_192b<>(SB),NOSPLIT,$0
	PSHUFD $0x55, X1, X1
	SHUFPS $0x10, X0, X4
	PXOR X4, X0
	SHUFPS $0x8c, X0, X4
	PXOR X4, X0
	PXOR X1, X0

	MOVAPS X2, X5
	PSLLDQ $0x4, X5
	PSHUFD $0xff, X0, X3
	PXOR X3, X2
	PXOR X5, X2

	MOVUPS X0, (BX)
	ADDQ $16, BX
	RET

TEXT _expand_key_256a<>(SB),NOSPLIT,$0
	JMP _expand_key_128<>(SB)

TEXT _expand_key_256b<>(SB),NOSPLIT,$0
	PSHUFD $0xaa, X1, X1
	SHUFPS $0x10, X2, X4
	PXOR X4, X2
	SHUFPS $0x8c, X2, X4
	PXOR X4, X2
	PXOR X1, X2

	MOVUPS X2, (BX)
	ADDQ $16, BX
	RET
