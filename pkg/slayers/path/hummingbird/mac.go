//go:build amd64 || arm64 || ppc64 || ppc64le

package hummingbird

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/scionproto/scion/pkg/addr"
)

// defined in asm_* assembly files

//go:noescape
func encryptBlockAsm(nr int, xk *uint32, dst, src *byte)

//TODO: test expandKeyAsm on arm64 and ppc64 machines. Compare with code in go/src/crypto/aes/asm_* if necessary

//go:noescape
func expandKeyAsm(nr int, key *byte, enc *uint32)

const AkBufferSize = 16
const FlyoverMacBufferSize = 32
const XkBufferSize = 44
const PathType = 5

var ZeroBlock [aes.BlockSize]byte

// Derive authentication key A_k
// block is expected to be initialized beforehand with aes.NewCipher(sv), where sv is this AS' secret value
func DeriveAuthKey(block cipher.Block, resId uint32, bw, in, eg uint16, startTime uint32, resDuration uint16, buffer []byte) []byte {

	if len(buffer) < AkBufferSize {
		buffer = make([]byte, AkBufferSize)
	}
	//prepare input
	binary.BigEndian.PutUint32(buffer[0:4], resId<<10|uint32(bw))
	binary.BigEndian.PutUint16(buffer[4:6], in)
	binary.BigEndian.PutUint16(buffer[6:8], eg)
	binary.BigEndian.PutUint32(buffer[8:12], startTime)
	binary.BigEndian.PutUint16(buffer[12:14], resDuration)
	binary.BigEndian.PutUint16(buffer[14:16], 0) //padding

	// should xor input with iv, but we use iv = 0 => identity
	block.Encrypt(buffer[0:16], buffer[0:16])
	return buffer[0:16]
}

// Computes full flyover mac vk
// Needs a xkbuffer of 44 uint32s to store the expanded keys for aes
// dummy buffer is memory used by key expansion to store decryption keys
func FullFlyoverMac(ak []byte, dstIA addr.IA, pktlen uint16, resStartTime uint16, highResTime uint32, buffer []byte, xkbuffer []uint32) []byte {
	if len(buffer) < FlyoverMacBufferSize {
		buffer = make([]byte, FlyoverMacBufferSize)
	}
	if len(xkbuffer) < XkBufferSize {
		xkbuffer = make([]uint32, XkBufferSize)
	}

	binary.BigEndian.PutUint64(buffer[0:8], uint64(dstIA))
	binary.BigEndian.PutUint16(buffer[8:10], pktlen)
	binary.BigEndian.PutUint16(buffer[10:12], resStartTime)
	binary.BigEndian.PutUint32(buffer[12:16], highResTime)

	expandKeyAsm(10, &ak[0], &xkbuffer[0])

	encryptBlockAsm(10, &xkbuffer[0], &buffer[0], &buffer[0])

	return buffer[0:16]
}
