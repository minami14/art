package art

import "fmt"

func (a *Art) And(operand ...string) error {
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

	if err := a.Set(operand[0], x&y); err != nil {
		return err
	}

	return nil
}

func (a *Art) Or(operand ...string) error {
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

	if err := a.Set(operand[0], x|y); err != nil {
		return err
	}

	return nil
}

func (a *Art) Xor(operand ...string) error {
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

	if err := a.Set(operand[0], x^y); err != nil {
		return err
	}

	return nil
}

func (a *Art) Not(operand ...string) error {
	if len(operand) != 1 {
		return fmt.Errorf("invalid operands length: %v", operand)
	}

	x, err := a.Get(operand[0])
	if err != nil {
		return err
	}

	if err := a.Set(operand[0], ^x); err != nil {
		return err
	}

	return nil
}
