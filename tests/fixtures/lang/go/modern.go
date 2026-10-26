package modern

import (
	"fmt"
	"iter"
	"slices"
)

type Number interface {
	~int | ~int64 | ~float64
}

type Stack[T any] struct{ items []T }

func (s *Stack[T]) Push(v T) { s.items = append(s.items, v) }

func (s *Stack[T]) All() iter.Seq[T] {
	return func(yield func(T) bool) {
		for _, v := range s.items {
			if !yield(v) {
				return
			}
		}
	}
}

func Sum[N Number](xs ...N) N {
	var t N
	for _, x := range xs {
		t += x
	}
	return t
}

func Use() {
	s := &Stack[int]{}
	s.Push(1)
	for v := range s.All() {
		fmt.Println(v)
	}
	for i := range 3 {
		_ = i
	}
	slices.Sort([]int{3, 1})
	_ = min(1, 2)
	_ = Sum(1, 2, 3)
}
