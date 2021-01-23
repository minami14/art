package art

import "fmt"

func (a *Art) Mov(operand ...string) error {
	if len(operand) != 2 {
		return fmt.Errorf("invalid operands length: %v", operand)
	}

	v, err := a.Get(operand[1])
	if err != nil {
		return err
	}

	if err := a.Set(operand[0], v); err != nil {
		return err
	}

	return nil
}

func (a *Art) Push(operand ...string) error {
	if len(operand) != 1 {
		return fmt.Errorf("invalid operands length: %v", operand)
	}

	v, err := a.Get(operand[0])
	if err != nil {
		return err
	}

	if err := a.Stack.Push(v); err != nil {
		return err
	}

	return nil
}

func (a *Art) Pop(operand ...string) error {
	if len(operand) != 1 {
		return fmt.Errorf("invalid operands length: %v", operand)
	}

	v, err := a.Stack.Pop()
	if err != nil {
		return err
	}

	if err := a.Set(operand[0], v); err != nil {
		return err
	}

	return nil
}

func (a *Art) Cbw(operand ...string) error { return nil }

func (a *Art) Cwde(operand ...string) error { return nil }

func (a *Art) Cdqe(operand ...string) error { return nil }

func (a *Art) Cwd(operand ...string) error { return nil }

func (a *Art) Cdq(operand ...string) error { return nil }

func (a *Art) Cqo(operand ...string) error { return nil }

func (a *Art) Movsx(operand ...string) error { return nil }

func (a *Art) Movzx(operand ...string) error { return nil }

func (a *Art) Lea(operand ...string) error { return nil }

func (a *Art) Bswap(operand ...string) error { return nil }

func (a *Art) Xchg(operand ...string) error { return nil }

func (a *Art) Nop(operand ...string) error { return nil }
