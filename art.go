package art

import (
	"errors"
	"fmt"
	"io"
)

type Art struct {
	Assembly      *Assembly
	Register      *Register
	Stack         *Stack
	Memory        []byte
	Operations    map[string]Operation
	SystemCalls   map[uint64]func() error
	UseHostKernel bool
}

func New() *Art {
	a := new(Art)
	setOperations(a)
	setSyscallLinux(a)
	return a
}

func (a *Art) Next() error {
	line, err := a.Assembly.Next()
	if err != nil {
		return err
	}

	return line.Operation(line.Operand...)
}

func (a *Art) Run() error {
	for {
		if err := a.Next(); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func (a *Art) AddAssemblyLine(opcode string, operand ...string) error {
	op, ok := a.Operations[opcode]
	if !ok {
		return fmt.Errorf("invalid opcode: %v", opcode)
	}

	if err := a.Assembly.Add(op, operand...); err != nil {
		return err
	}

	return nil
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
