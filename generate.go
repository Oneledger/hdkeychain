/*

 */

package hdwallet

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"strings"

	"github.com/bgadrian/go-mnemonic/bip39"
)

// NewHDWallet
func NewHDWallet(passphrase string) (HDWallet, error) {
	newRandomMnemonic, err := bip39.NewMnemonicRandom(256, passphrase)
	if err != nil {
		return nil, err
	}

	password, err := newRandomMnemonic.GetSentence()
	if err != nil {
		return nil, err
	}

	seed, err := newRandomMnemonic.GetSeed()
	if err != nil {
		return nil, err
	}
	seedBytes, err := hex.DecodeString(seed)

	return &Wallet{seedBytes, strings.Split(password, " ")}, nil
}

// NewHDWallet
func NewHDWalletFromKeywords(keywords []string, passphrase string) (HDWallet, error) {
	newRandomMnemonic, err := bip39.NewMnemonicFromSentence(strings.Join(keywords, " "), passphrase)
	if err != nil {
		return nil, err
	}

	seed, err := newRandomMnemonic.GetSeed()
	if err != nil {
		return nil, err
	}
	seedBytes, err := hex.DecodeString(seed)

	return &Wallet{seedBytes, keywords}, nil
}

// Secp256k1CurvePhrase is the master key used along with a random seed used to generate
// the master node in the hierarchical tree.
var Secp256k1CurvePhrase = []byte("Bitcoin seed")
var ED25519CurvePhrase   = []byte("ed25519 seed")

func MasterKeyGenerate(seedBytes []byte, masterKey []byte) *ExtendedKey {
	// First take the HMAC-SHA512 of the master key and the seed data:
	//   I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
	hmac512 := hmac.New(sha512.New, masterKey)
	hmac512.Write(seedBytes)
	lr := hmac512.Sum(nil)

	// Split "I" into two 32-byte sequences Il and Ir where:
	//   Il = master secret key
	//   Ir = master chain code
	secretKey := lr[:len(lr)/2]
	chainCode := lr[len(lr)/2:]

	parentFP := []byte{0x00, 0x00, 0x00, 0x00}
	master := NewExtendedKey(secretKey, chainCode,
		parentFP, 0, 0, true)

	return master
}
