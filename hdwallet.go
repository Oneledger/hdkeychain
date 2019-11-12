/*

 */

package hdwallet

import (
	"github.com/btcsuite/btcd/btcec"
	xEd25519 "golang.org/x/crypto/ed25519"
)

type HDWallet interface {
	GetKeywords() []string

	GetKeywordsString() string

	// btc
	GetBTCExternalKeyPair(i uint32) (*btcec.PrivateKey, *btcec.PublicKey, error)

	GetBTCChangeKeyPair(i uint32) (*btcec.PrivateKey, *btcec.PublicKey, error)

	// eth
	GetETHKeyPair(i uint32) (*btcec.PrivateKey, *btcec.PublicKey, error)

	// olt
	GetOLTKeyPair(i uint32) (*xEd25519.PrivateKey, xEd25519.PublicKey, error)
}

var _ HDWallet = &Wallet{}

// ChildKey interface
type ChildKey interface {
	Child(k ExtendedKey, i uint32) (*ExtendedKey, error)
}

var _ ChildKey = &Secp256K1{}
