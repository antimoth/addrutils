package addrutils

import (
	"encoding/hex"
	"github.com/ofgp/common/defines"
)

func Hex2Bytes(str string) []byte {
	h, _ := hex.DecodeString(str)

	return h
}

func FromHex(s string) []byte {
	if len(s) > 1 {
		if s[0:2] == "0x" || s[0:2] == "0X" {
			s = s[2:]
		}
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return Hex2Bytes(s)
}

func CheckBytesToStr(checkBytes []byte, chainCode uint8) (string, error) {
	switch chainCode {
	case defines.CHAIN_CODE_BTC:
		addr, err := BtcAddressFromCheckBytes(checkBytes)
		if err != nil {
			return "", err
		}
		return addr.String(), nil

	case defines.CHAIN_CODE_BCH:
		addr, err := BchAddressFromCheckBytes(checkBytes)
		if err != nil {
			return "", err
		}
		return addr.String(), nil

	case defines.CHAIN_CODE_ETH:
		addr, err := EthAddressFromCheckBytes(checkBytes)
		if err != nil {
			return "", err
		}
		return addr.Hex(), nil

	default:
		return "", ErrUnknownChainCode
	}
}

func StrToCheckBytes(sAddr string, chainCode uint8) ([]byte, error) {
	switch chainCode {
	case defines.CHAIN_CODE_BTC:
		return StrBtcAddrToCheckBytes(sAddr)

	case defines.CHAIN_CODE_BCH:
		return StrBchAddrToCheckBytes(sAddr)

	case defines.CHAIN_CODE_ETH:
		return StrEthAddrToCheckBytes(sAddr)

	default:
		return []byte{}, ErrUnknownChainCode
	}
}
