package art

import (
	"fmt"
	"math"
)

func (a *Art) Add(operand ...string) error {
	if len(operand) != 2 {
		return fmt.Errorf("invalid operands length: %v", operand)
	}

	x, err := a.Get(operand[0])
	if err != nil {
		return err
	}

	y, err := a.Get(operand[1])
	if err != nil {
		return err
	}

	if err := a.Set(operand[0], x+y); err != nil {
		return err
	}

	cf := math.MaxUint64-x < y
	a.Register.SetFlag(CF, cf)

	return nil
}

func (a *Art) Adc(operand ...string) error {
	if len(operand) != 2 {
		return fmt.Errorf("invalid operands length: %v", operand)
	}

	x, err := a.Get(operand[0])
	if err != nil {
		return err
	}

	y, err := a.Get(operand[1])
	if err != nil {
		return err
	}

	var z uint64
	if a.Register.Flag(CF) {
		z = 1
	}

	if err := a.Set(operand[0], x+y+z); err != nil {
		return err
	}

	cf := math.MaxUint64-x < y || math.MaxUint64-x-y < z
	a.Register.SetFlag(CF, cf)

	return nil
}

func (a *Art) Sub(operand ...string) error {
	if len(operand) != 2 {
		return fmt.Errorf("invalid operands length: %v", operand)
	}

	x, err := a.Get(operand[0])
	if err != nil {
		return err
	}

	y, err := a.Get(operand[1])
	if err != nil {
		return err
	}

	if err := a.Set(operand[0], x-y); err != nil {
		return err
	}

	a.Register.SetFlag(CF, x < y)

	return nil
}

func (a *Art) Sbb(operand ...string) error {
	if len(operand) != 2 {
		return fmt.Errorf("invalid operands length: %v", operand)
	}

	x, err := a.Get(operand[0])
	if err != nil {
		return err
	}

	y, err := a.Get(operand[1])
	if err != nil {
		return err
	}

	var z uint64
	if a.Register.Flag(CF) {
		z = 1
	}

	if err := a.Set(operand[0], x-y-z); err != nil {
		return err
	}

	cf := x < y || (z == 1 && x == y)
	a.Register.SetFlag(CF, cf)

	return nil
}

func (a *Art) Inc(operand ...string) error {
	if len(operand) != 1 {
		return fmt.Errorf("invalid operands length: %v", operand)
	}

	x, err := a.Get(operand[0])
	if err != nil {
		return err
	}

	if err := a.Set(operand[0], x+1); err != nil {
		return err
	}

	return nil
}

func (a *Art) Dec(operand ...string) error {
	if len(operand) != 1 {
		return fmt.Errorf("invalid operands length: %v", operand)
	}

	x, err := a.Get(operand[0])
	if err != nil {
		return err
	}

	if err := a.Set(operand[0], x-1); err != nil {
		return err
	}

	return nil
}

func (a *Art) Neg(operand ...string) error {
	if len(operand) != 1 {
		return fmt.Errorf("invalid operands length: %v", operand)
	}

	x, err := a.Get(operand[0])
	if err != nil {
		return err
	}

	if err := a.Set(operand[0], 1+^x); err != nil {
		return err
	}

	a.Register.SetFlag(CF, x != 0)

	return nil
}
