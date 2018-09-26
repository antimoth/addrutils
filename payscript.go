package swaputils

import (
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"golang.org/x/crypto/ripemd160"
)

func PayToAddrScriptFromCheckBytes(bCheckAddr []byte) ([]byte, error) {
	decoded, netID, err := DecodeCheckAddrBytes(bCheckAddr)
	if err != nil {
		return nil, err
	}

	if len(decoded) != ripemd160.Size {
		return nil, ErrHash160Size
	}

	switch netID {
	case chaincfg.MainNetParams.PubKeyHashAddrID, chaincfg.TestNet3Params.PubKeyHashAddrID, chaincfg.RegressionNetParams.PubKeyHashAddrID:
		return payToPubKeyHashScript(decoded)

	case chaincfg.MainNetParams.ScriptHashAddrID, chaincfg.TestNet3Params.ScriptHashAddrID, chaincfg.RegressionNetParams.ScriptHashAddrID:
		return payToScriptHashScript(decoded)

	case BCH_MAINNET_P2PKH_NET_ID, BCH_TESTNET_P2PKH_NET_ID, BCH_REGNET_P2PKH_NET_ID:
		return payToPubKeyHashScript(decoded)

	case BCH_MAINNET_P2SH_NET_ID, BCH_TESTNET_P2SH_NET_ID, BCH_REGNET_P2SH_NET_ID:
		return payToScriptHashScript(decoded)

	}

	return nil, ErrUnknownNetID
}

func payToPubKeyHashScript(pubKeyHash []byte) ([]byte, error) {
	return txscript.NewScriptBuilder().AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160).
		AddData(pubKeyHash).AddOp(txscript.OP_EQUALVERIFY).AddOp(txscript.OP_CHECKSIG).
		Script()
}

func payToScriptHashScript(scriptHash []byte) ([]byte, error) {
	return txscript.NewScriptBuilder().AddOp(txscript.OP_HASH160).AddData(scriptHash).
		AddOp(txscript.OP_EQUAL).Script()
}
