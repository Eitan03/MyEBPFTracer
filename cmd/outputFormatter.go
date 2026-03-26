package cmd

import (
	"MyGoTracer/internal/ebpf"
	"fmt"
)

type Formatter func(ebpf.FunctionInvocation) string

func jsonFormatter(invocation ebpf.FunctionInvocation) string {
	return fmt.Sprintf("{\"function\": \"%s\", \"tid\": %d, \"address\": %d}", invocation.Name, invocation.Tid, invocation.Address)
}

func textFormatter(invocation ebpf.FunctionInvocation) string {
	return fmt.Sprintf("function %s was called from %d in address 0x%x", invocation.Name, invocation.Tid, invocation.Address)
}

var (
	outpotFormats = map[string]Formatter{
		"text": textFormatter,
		"json": jsonFormatter,
	}
)

func GetFormatter(formatterType string) Formatter {
	return outpotFormats[formatterType]
}
