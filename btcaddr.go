package addrutils

import (
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

func BtcAddressFromCheckBytes(bCheckAddr []byte) (btcutil.Address, error) {
	decoded, netID, err := DecodeCheckAddrBytes(bCheckAddr)
	if err != nil {
		return nil, err
	}

	switch len(decoded) {
	case ripemd160.Size:
		isP2PKH := chaincfg.IsPubKeyHashAddrID(netID)
		isP2SH := chaincfg.IsScriptHashAddrID(netID)
		switch hash160 := decoded; {
		case isP2PKH && isP2SH:
			return nil, btcutil.ErrAddressCollision
		case isP2PKH:
			return newAddressPubKeyHash(hash160, netID)
		case isP2SH:
			return newAddressScriptHashFromHash(hash160, netID)
		default:
			return nil, btcutil.ErrUnknownAddressType
		}

	default:
		return nil, ErrHash160Size
	}
}

func StrBtcAddrToCheckBytes(addr string) (checkBytes []byte, err error) {
	decoded := base58.Decode(addr)
	if len(decoded) < 5 {
		return nil, base58.ErrInvalidFormat
	}

	var cksum [4]byte
	copy(cksum[:], decoded[len(decoded)-4:])
	if checksum(decoded[:len(decoded)-4]) != cksum {
		return nil, base58.ErrChecksum
	}
	checkBytes = append(checkBytes, decoded...)
	return
}

func BtcAddressFromStr(addr string) (btcutil.Address, error) {
	checkBytes, err := StrBtcAddrToCheckBytes(addr)
	if err != nil {
		return nil, err
	}
	return BtcAddressFromCheckBytes(checkBytes)
}

type AddressPubKeyHash struct {
	hash  [ripemd160.Size]byte
	netID byte
}

func (a *AddressPubKeyHash) EncodeAddress() string {
	return base58.CheckEncode(a.hash[:ripemd160.Size], a.netID)
}

func (a *AddressPubKeyHash) ScriptAddress() []byte {
	return a.hash[:]
}

func (a *AddressPubKeyHash) IsForNet(net *chaincfg.Params) bool {
	return a.netID == net.PubKeyHashAddrID
}

func (a *AddressPubKeyHash) String() string {
	return a.EncodeAddress()
}

func (a *AddressPubKeyHash) Hash160() *[ripemd160.Size]byte {
	return &a.hash
}

func newAddressPubKeyHash(pkHash []byte, netID byte) (*AddressPubKeyHash, error) {
	if len(pkHash) != ripemd160.Size {
		return nil, ErrHash160Size
	}

	addr := &AddressPubKeyHash{netID: netID}
	copy(addr.hash[:], pkHash)
	return addr, nil
}

type AddressScriptHash struct {
	hash  [ripemd160.Size]byte
	netID byte
}

func (a *AddressScriptHash) EncodeAddress() string {
	return base58.CheckEncode(a.hash[:ripemd160.Size], a.netID)
}

func (a *AddressScriptHash) ScriptAddress() []byte {
	return a.hash[:]
}

func (a *AddressScriptHash) IsForNet(net *chaincfg.Params) bool {
	return a.netID == net.ScriptHashAddrID
}

func (a *AddressScriptHash) String() string {
	return a.EncodeAddress()
}

func (a *AddressScriptHash) Hash160() *[ripemd160.Size]byte {
	return &a.hash
}

func newAddressScriptHashFromHash(scriptHash []byte, netID byte) (*AddressScriptHash, error) {
	if len(scriptHash) != ripemd160.Size {
		return nil, ErrHash160Size
	}

	addr := &AddressScriptHash{netID: netID}
	copy(addr.hash[:], scriptHash)
	return addr, nil
}
