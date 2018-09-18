package swaputils

import (
	"github.com/ofgp/common/defines"
)

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
