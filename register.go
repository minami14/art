package art

import (
	"fmt"
	"math"
	"strings"
)

type registerIndex struct {
	index int
	mask  uint64
	shift int
}

var registerIndices = map[string]registerIndex{
	"RAX":   {0, math.MaxUint64, 0},
	"EAX":   {0, math.MaxUint32, 0},
	"AX":    {0, math.MaxUint16, 0},
	"AH":    {0, math.MaxUint16, 8},
	"AL":    {0, math.MaxUint8, 0},
	"RBX":   {1, math.MaxUint64, 0},
	"EBX":   {1, math.MaxUint32, 0},
	"BX":    {1, math.MaxUint16, 0},
	"BH":    {1, math.MaxUint16, 8},
	"BL":    {1, math.MaxUint8, 0},
	"RCX":   {2, math.MaxUint64, 0},
	"ECX":   {2, math.MaxUint32, 0},
	"CX":    {2, math.MaxUint16, 0},
	"CH":    {2, math.MaxUint16, 8},
	"CL":    {2, math.MaxUint8, 0},
	"RDX":   {3, math.MaxUint64, 0},
	"EDX":   {3, math.MaxUint32, 0},
	"DX":    {3, math.MaxUint16, 0},
	"DH":    {3, math.MaxUint16, 8},
	"DL":    {3, math.MaxUint8, 0},
	"RSI":   {4, math.MaxUint64, 0},
	"ESI":   {4, math.MaxUint32, 0},
	"SI":    {4, math.MaxUint16, 0},
	"SIL":   {4, math.MaxUint8, 0},
	"RDI":   {5, math.MaxUint64, 0},
	"EDI":   {5, math.MaxUint32, 0},
	"DI":    {5, math.MaxUint16, 0},
	"DIL":   {5, math.MaxUint8, 0},
	"RBP":   {6, math.MaxUint64, 0},
	"ESP":   {6, math.MaxUint32, 0},
	"SP":    {6, math.MaxUint16, 0},
	"SPL":   {6, math.MaxUint8, 0},
	"FLAGS": {7, math.MaxUint64, 0},
}

const (
	CF = 1 << iota
	_
	PF
	_
	AF
	_
	ZF
	SF
	TF
	IF
	DF
	OF
	IOPL
	NT
	_
	RF
	VM
	AC
	VIF
	VIP
	ID
)

func init() {
	for i := 8; i < 16; i++ {
		rn := fmt.Sprintf("R%v", i)
		registerIndices[rn] = registerIndex{i, math.MaxUint64, 0}
		registerIndices[rn+"D"] = registerIndex{i, math.MaxUint32, 0}
		registerIndices[rn+"W"] = registerIndex{i, math.MaxUint16, 0}
		registerIndices[rn+"B"] = registerIndex{i, math.MaxUint8, 0}
	}
}

type Register [16]uint64

func IsRegisterMnemonic(mnemonic string) bool {
	mnemonic = strings.ToUpper(mnemonic)
	_, ok := registerIndices[mnemonic]
	return ok
}

func (r *Register) Get(mnemonic string) uint64 {
	mnemonic = strings.ToUpper(mnemonic)
	i, ok := registerIndices[mnemonic]
	if !ok {
		return 0
	}
	return (r[i.index] & i.mask) >> i.shift
}

func (r *Register) Set(mnemonic string, value uint64) {
	mnemonic = strings.ToUpper(mnemonic)
	i, ok := registerIndices[mnemonic]
	if !ok {
		return
	}
	r[i.index] = r[i.index]&^i.mask | value<<i.shift
}

func (r *Register) Flag(flag uint64) bool {
	return r[7]&flag != 0
}

func (r *Register) SetFlag(flag uint64, value bool) {
	if value {
		r[7] = r[7] | flag
	} else {
		r[7] = r[7] &^ flag
	}
}
