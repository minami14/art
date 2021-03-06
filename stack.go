package art

import (
	"errors"
	"math"
)

type Stack struct {
	MaxSize int
	Buffer  []uint64
}

func NewStack() *Stack {
	return &Stack{MaxSize: math.MaxUint64}
}

var (
	ErrStackUnderflow = errors.New("stack underflow")
	ErrStackOverflow  = errors.New("stack overflow")
)

func (s *Stack) Pop() (uint64, error) {
	if len(s.Buffer) == 0 {
		return 0, ErrStackUnderflow
	}
	return s.Buffer[len(s.Buffer)-1], nil
}

func (s *Stack) Push(src uint64) error {
	if s.MaxSize <= len(s.Buffer) {
		return ErrStackOverflow
	}
	s.Buffer = append(s.Buffer, src)
	return nil
}
