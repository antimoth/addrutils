package addrutils

import (
	"github.com/btcsuite/btcutil/base58"
)

func DecodeCheckAddrBytes(bCheckAddr []byte) (decoded []byte, netID byte, err error) {
	if len(bCheckAddr) < 5 {
		return []byte{}, 0, base58.ErrInvalidFormat
	}
	netID = bCheckAddr[0]
	var cksum [4]byte
	copy(cksum[:], bCheckAddr[len(bCheckAddr)-4:])
	if checksum(bCheckAddr[:len(bCheckAddr)-4]) != cksum {
		return []byte{}, 0, base58.ErrChecksum
	}
	payload := bCheckAddr[1 : len(bCheckAddr)-4]
	decoded = append(decoded, payload...)
	return
}
