package swaputils

import (
	"errors"
	"github.com/antimoth/logger"
)

var utilLogger = logger.NewLogger("INFO", "swaputils")

var (
	ErrHash160Size        = errors.New("decoded address is of unknown size")
	ErrUnknownAddrPrefix  = errors.New("unknown addr prefix")
	ErrEncodeSizeOverflow = errors.New("encoded size out of valid range")
	ErrBchEncodePadding   = errors.New("encoding padding error")
	ErrEthNetID           = errors.New("error eth net id")
)
