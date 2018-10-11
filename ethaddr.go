package addrutils

import (
	"github.com/ethereum/go-ethereum/common"
)

func EthAddressFromCheckBytes(bCheckAddr []byte) (common.Address, error) {
	decoded, _, _ := DecodeCheckAddrBytes(bCheckAddr)

	return common.BytesToAddress(decoded), nil
}

func StrEthAddrToCheckBytes(addr string) (checkBytes []byte, err error) {
	decoded := common.HexToAddress(addr).Bytes()
	checkBytes = append(checkBytes, ETH_NET_ID)
	checkBytes = append(checkBytes, decoded[:]...)
	cksum := checksum(checkBytes)
	checkBytes = append(checkBytes, cksum[:]...)
	return
}

func EthAddressFromStr(addr string) (common.Address, error) {
	return common.HexToAddress(addr), nil
}
