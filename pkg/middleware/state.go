package middleware

import (
	"crypto/rsa"
	"sync"
)

var (
	masterPrivateKey *rsa.PrivateKey
	blindIndexKey    []byte
	SharedDEK        []byte
	EncryptionMode   string

	cacheMu        sync.RWMutex
	tableOIDsCache = make(map[string]map[int32]string)
	metadataCache  = make(map[string]TableMetadata)
)
