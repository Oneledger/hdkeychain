/*

 */

package hdwallet

import "strings"

type changeType int

const (
	purposeBIP44 = 44

	externalChain changeType = 0
	internalChain changeType = 1

	coinTypeBTC = 0
	coinTypeETH = 60
	coinTypeOLT = 403
)

type Wallet struct {
	Seed      []byte
	keywords []string
}

var _ HDWallet = &Wallet{}



func (w *Wallet) GetKeywords() []string {
	return w.keywords
}

func (w *Wallet) GetKeywordsString() string {
	return strings.Join(w.keywords, " ")
}


func hardenIndex(i uint32) uint32 {
	return uint32(i) + uint32(HardenedKeyStart)
}
