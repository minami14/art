package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

const syscall64tbl = "https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/entry/syscalls/syscall_64.tbl"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

type systemCall struct {
	number     string
	abi        string
	name       string
	entryPoint string
}

func run() error {
	resp, err := http.Get(syscall64tbl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var syscalls []systemCall
	for _, row := range strings.Split(string(body), "\n") {
		if row == "" {
			continue
		}

		if row[0] == '#' {
			continue
		}

		col := strings.Split(row, "\t")
		for i := len(col) - 1; i >= 0; i-- {
			if col[i] == "" {
				col = append(col[:i], col[i+1:]...)
			}
		}

		s := systemCall{
			number: col[0],
			abi:    col[1],
			name:   col[2],
		}

		s.name = strings.ReplaceAll(s.name, "_", " ")
		s.name = strings.Title(s.name)
		s.name = strings.ReplaceAll(s.name, " ", "")

		if s.abi != "common" {
			s.name = s.name + strings.Title(s.abi)
		}

		if len(col) == 4 {
			s.entryPoint = col[3]
		}

		syscalls = append(syscalls, s)
	}

	buf, err := generate(syscalls)
	if err != nil {
		return err
	}

	fmt.Println(buf.String())

	return nil
}

func generate(syscalls []systemCall) (*bytes.Buffer, error) {
	buf := bytes.NewBufferString("package art\n\nfunc setSyscall(a *Art) {\n\ta.Syscall = map[uint64]func() error{\n")
	for _, s := range syscalls {
		str := fmt.Sprintf("\t\t%v: a.syscall%v,\n", s.number, s.name)
		if _, err := buf.WriteString(str); err != nil {
			return nil, err
		}
	}

	if _, err := buf.WriteString("\t}\n}\n\n"); err != nil {
		return nil, err
	}

	for _, s := range syscalls {
		str := fmt.Sprintf("func (a *Art) syscall%v() error { return nil }\n\n", s.name)
		if _, err := buf.WriteString(str); err != nil {
			return nil, err
		}
	}

	return buf, nil
}
