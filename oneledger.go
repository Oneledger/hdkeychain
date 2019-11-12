/*

 */

package hdwallet

import (
	xEd25519 "golang.org/x/crypto/ed25519"
)

func (w *Wallet) GetOLTKeyPair(i uint32) (*xEd25519.PrivateKey, xEd25519.PublicKey, error) {
	key, err := w.ethPrivKey(i)
	if err != nil {
		return nil, nil, err
	}

	privKey := xEd25519.NewKeyFromSeed(key.key)

	publicKey := make(xEd25519.PublicKey, xEd25519.PublicKeySize)
	copy(publicKey, privKey[32:])

	return &privKey, publicKey, nil
}

func (w *Wallet) oltPrivKey(i uint32) (*ExtendedKey, error) {

	gen := &Secp256K1{}


	master := MasterKeyGenerate(w.Seed, ED25519CurvePhrase)

	purposeKey, err := gen.Child(*master, hardenIndex(purposeBIP44))
	if err != nil {
		return nil, err
	}

	btcKey, err := gen.Child(*purposeKey, hardenIndex(coinTypeOLT))
	if err != nil {
		return nil, err
	}

	accountKey, err := gen.Child(*btcKey, hardenIndex(0))
	if err != nil {
		return nil, err
	}

	changeKey, err := gen.Child(*accountKey, hardenIndex(uint32(externalChain)))
	if err != nil {
		return nil, err
	}

	indexKey, err := gen.Child(*changeKey, hardenIndex(i))
	if err != nil {
		return nil, err
	}

	return indexKey, nil
}
