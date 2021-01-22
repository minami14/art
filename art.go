package art

import "fmt"

type Art struct {
	Register   *Register
	Stack      *Stack
	Memory     []byte
	Operations map[string]Operation
}

func New() *Art {
	a := new(Art)
	setOperations(a)
	return a
}

func (a *Art) Run() error {
	return nil
}

func (a *Art) Do(opcode string, operand ...string) error {
	op, ok := a.Operations[opcode]
	if !ok {
		return fmt.Errorf("invalid opcode: %v", opcode)
	}

	return op(operand...)
}

func (a *Art) Get(mnemonic string) (uint64, error) {
	if IsRegisterMnemonic(mnemonic) {
		return a.Register.Get(mnemonic), nil
	}
	return 0, nil
}

func (a *Art) Set(mnemonic string, value uint64) error {
	if IsRegisterMnemonic(mnemonic) {
		a.Register.Set(mnemonic, value)
	}
	return nil
}
