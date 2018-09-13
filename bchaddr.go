package swaputils

import (
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/cpacia/bchutil"
	"golang.org/x/crypto/ripemd160"
)

func BchAddressFromCheckBytes(bCheckAddr []byte) (btcutil.Address, error) {
	decoded, netID, err := DecodeCheckAddrBytes(bCheckAddr)
	if err != nil {
		return nil, err
	}

	switch len(decoded) {
	case ripemd160.Size:
		switch netID {
		case BCH_MAINNET_P2PKH_NET_ID:
			return newCashAddressPubKeyHash(decoded, bchutil.Prefixes[chaincfg.MainNetParams.Name])
		case BCH_MAINNET_P2SH_NET_ID:
			return newCashAddressScriptHashFromHash(decoded, bchutil.Prefixes[chaincfg.MainNetParams.Name])
		case BCH_TESTNET_P2PKH_NET_ID:
			return newCashAddressPubKeyHash(decoded, bchutil.Prefixes[chaincfg.TestNet3Params.Name])
		case BCH_TESTNET_P2SH_NET_ID:
			return newCashAddressScriptHashFromHash(decoded, bchutil.Prefixes[chaincfg.TestNet3Params.Name])
		case BCH_REGNET_P2PKH_NET_ID:
			return newCashAddressPubKeyHash(decoded, bchutil.Prefixes[chaincfg.RegressionNetParams.Name])
		case BCH_REGNET_P2SH_NET_ID:
			return newCashAddressScriptHashFromHash(decoded, bchutil.Prefixes[chaincfg.RegressionNetParams.Name])
		default:
			return nil, btcutil.ErrUnknownAddressType
		}

	default:
		return nil, ErrHash160Size
	}
}

func StrBchAddrToCheckBytes(addr string) (checkBytes []byte, err error) {

	decoded, prefix, typ, err := bchutil.CheckDecodeCashAddress(addr)
	if err != nil {
		return nil, err
	}

	netID, err := getBchNetID(prefix, typ)
	if err != nil {
		return nil, err
	}

	checkBytes = append(checkBytes, netID)
	checkBytes = append(checkBytes, decoded[:]...)
	cksum := checksum(checkBytes)
	checkBytes = append(checkBytes, cksum[:]...)
	return
}

func BchAddressFromStr(addr string) (btcutil.Address, error) {

	decoded, prefix, typ, err := bchutil.CheckDecodeCashAddress(addr)
	if err != nil {
		return nil, err
	}

	switch len(decoded) {
	case ripemd160.Size:
		switch typ {
		case bchutil.P2PKH:
			return newCashAddressPubKeyHash(decoded, prefix)
		case bchutil.P2SH:
			return newCashAddressScriptHashFromHash(decoded, prefix)
		default:
			return nil, bchutil.ErrUnknownAddressType
		}

	default:
		return nil, ErrHash160Size
	}
}

func getBchNetID(prefix string, typ bchutil.AddressType) (uint8, error) {
	if prefix == bchutil.Prefixes[chaincfg.MainNetParams.Name] {
		if typ == bchutil.P2PKH {
			return BCH_MAINNET_P2PKH_NET_ID, nil
		} else if typ == bchutil.P2SH {
			return BCH_MAINNET_P2SH_NET_ID, nil
		} else {
			return BCH_ERROR_NET_ID, bchutil.ErrUnknownAddressType
		}
	} else if prefix == bchutil.Prefixes[chaincfg.TestNet3Params.Name] {
		if typ == bchutil.P2PKH {
			return BCH_TESTNET_P2PKH_NET_ID, nil
		} else if typ == bchutil.P2SH {
			return BCH_TESTNET_P2SH_NET_ID, nil
		} else {
			return BCH_ERROR_NET_ID, bchutil.ErrUnknownAddressType
		}
	} else if prefix == bchutil.Prefixes[chaincfg.RegressionNetParams.Name] {
		if typ == bchutil.P2PKH {
			return BCH_REGNET_P2PKH_NET_ID, nil
		} else if typ == bchutil.P2SH {
			return BCH_REGNET_P2SH_NET_ID, nil
		} else {
			return BCH_ERROR_NET_ID, bchutil.ErrUnknownAddressType
		}
	} else {
		return BCH_ERROR_NET_ID, ErrUnknownAddrPrefix
	}
}

func BchAddrEncode(prefix string, payload []byte) string {
	checksum := bchutil.CreateChecksum(prefix, payload)
	combined := bchutil.Cat(payload, checksum)
	ret := prefix + ":"

	for _, c := range combined {
		ret += string(bchutil.CHARSET[c])
	}

	return ret
}

func CheckEncodeCashAddress(input []byte, prefix string, t bchutil.AddressType) string {
	k, err := packAddressData(t, input)
	if err != nil {
		utilLogger.Warn("pack bch address error", "error", err)
		return ""
	}
	return BchAddrEncode(prefix, k)
}

func convertBits(data []byte, fromBits uint, tobits uint, pad bool) ([]byte, error) {
	// General power-of-2 base conversion.
	var uintArr []uint
	for _, i := range data {
		uintArr = append(uintArr, uint(i))
	}
	acc := uint(0)
	bits := uint(0)
	var ret []uint
	maxv := uint((1 << tobits) - 1)
	maxAcc := uint((1 << (fromBits + tobits - 1)) - 1)
	for _, value := range uintArr {
		acc = ((acc << fromBits) | value) & maxAcc
		bits += fromBits
		for bits >= tobits {
			bits -= tobits
			ret = append(ret, (acc>>bits)&maxv)
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, (acc<<(tobits-bits))&maxv)
		}
	} else if bits >= fromBits || ((acc<<(tobits-bits))&maxv) != 0 {
		return []byte{}, ErrBchEncodePadding
	}
	var dataArr []byte
	for _, i := range ret {
		dataArr = append(dataArr, byte(i))
	}
	return dataArr, nil
}

func packAddressData(addrType bchutil.AddressType, addrHash []byte) ([]byte, error) {
	// Pack addr data with version byte.
	if addrType != bchutil.P2PKH && addrType != bchutil.P2SH {
		return []byte{}, bchutil.ErrUnknownAddressType
	}
	versionByte := uint(addrType) << 3
	encodedSize := (uint(len(addrHash)) - 20) / 4
	if (len(addrHash)-20)%4 != 0 {
		return []byte{}, ErrHash160Size
	}
	if encodedSize < 0 || encodedSize > 8 {
		return []byte{}, ErrEncodeSizeOverflow
	}
	versionByte |= encodedSize
	var addrHashUint []byte
	for _, e := range addrHash {
		addrHashUint = append(addrHashUint, byte(e))
	}
	data := append([]byte{byte(versionByte)}, addrHashUint...)
	packedData, err := convertBits(data, 8, 5, true)
	if err != nil {
		return []byte{}, err
	}
	return packedData, nil
}

type CashAddressPubKeyHash struct {
	bchutil.CashAddressPubKeyHash
	hash   [ripemd160.Size]byte
	prefix string
}

func (a *CashAddressPubKeyHash) EncodeAddress() string {
	return CheckEncodeCashAddress(a.hash[:ripemd160.Size], a.prefix, bchutil.P2PKH)
}

func (a *CashAddressPubKeyHash) ScriptAddress() []byte {
	return a.hash[:]
}

func (a *CashAddressPubKeyHash) IsForNet(net *chaincfg.Params) bool {
	checkPre, ok := bchutil.Prefixes[net.Name]
	if !ok {
		return false
	}
	return a.prefix == checkPre
}

func (a *CashAddressPubKeyHash) String() string {
	return a.EncodeAddress()
}

func (a *CashAddressPubKeyHash) Hash160() *[ripemd160.Size]byte {
	return &a.hash
}

func newCashAddressPubKeyHash(pkHash []byte, prefix string) (*CashAddressPubKeyHash, error) {
	if len(pkHash) != ripemd160.Size {
		return nil, ErrHash160Size
	}

	addr := &CashAddressPubKeyHash{prefix: prefix}
	copy(addr.hash[:], pkHash)
	return addr, nil
}

type CashAddressScriptHash struct {
	hash   [ripemd160.Size]byte
	prefix string
}

func (a *CashAddressScriptHash) EncodeAddress() string {
	return CheckEncodeCashAddress(a.hash[:ripemd160.Size], a.prefix, bchutil.P2SH)
}

func (a *CashAddressScriptHash) ScriptAddress() []byte {
	return a.hash[:]
}

func (a *CashAddressScriptHash) IsForNet(net *chaincfg.Params) bool {
	pre, ok := bchutil.Prefixes[net.Name]
	if !ok {
		return false
	}
	return pre == a.prefix
}

func (a *CashAddressScriptHash) String() string {
	return a.EncodeAddress()
}

func (a *CashAddressScriptHash) Hash160() *[ripemd160.Size]byte {
	return &a.hash
}

func newCashAddressScriptHashFromHash(scriptHash []byte, prefix string) (*CashAddressScriptHash, error) {
	if len(scriptHash) != ripemd160.Size {
		return nil, ErrHash160Size
	}

	addr := &CashAddressScriptHash{prefix: prefix}
	copy(addr.hash[:], scriptHash)
	return addr, nil
}
