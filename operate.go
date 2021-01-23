package art

type Operation func(...string) error

func setOperations(a *Art) {
	a.Operations = map[string]Operation{
		"SYSCALL": a.Syscall,
	}
}
