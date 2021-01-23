package art

import (
	"fmt"
	"io"
)

type Assembly struct {
	Lines   []AssemblyLine
	Labels  map[string]int
	current int
}

type AssemblyLine struct {
	Operation Operation
	Operand   []string
}

func (a *Assembly) Add(op Operation, operand ...string) error {
	a.Lines = append(a.Lines, AssemblyLine{op, operand})
	return nil
}

func (a *Assembly) AddLabel(label string) error {
	if i, ok := a.Labels[label]; ok {
		return fmt.Errorf("the label is already registered: line %v, %v", i, label)
	}

	a.Labels[label] = len(a.Lines)
	return nil
}

func (a *Assembly) Next() (AssemblyLine, error) {
	if a.current >= len(a.Lines) {
		return AssemblyLine{}, io.EOF
	}

	line := a.Lines[a.current]
	a.current++

	return line, nil
}

func (a *Assembly) Jump(label string) error {
	i, ok := a.Labels[label]
	if !ok {
		return fmt.Errorf("the label is not registered: %v", label)
	}

	a.current = i
	return nil
}
