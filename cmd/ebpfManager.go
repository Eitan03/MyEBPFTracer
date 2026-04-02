package cmd

import (
	"MyGoTracer/internal/ebpf"
	elfLoader "MyGoTracer/internal/elfLoader"
	"context"
	"fmt"
	"log/slog"
)

func setupEbpf(filePath string, pid uint32, functionFilter elfLoader.FunctionFilter, ctx context.Context) (*ebpf.RunningProgram, error) {

	elfFile, err := elfLoader.LoadGoFile(filePath, functionFilter)
	if err != nil {
		return nil, fmt.Errorf("error extracting functions from ELF: %v", err)
	}

	for _, s := range elfFile.Symbols {
		slog.Info(fmt.Sprintf("function name: %s, function address 0x%x", s.Name, s.Address))
	}

	program, err := ebpf.LoadElfFile(*elfFile, pid, ctx)
	if err != nil {
		return nil, fmt.Errorf("error loading ebpf file: %v", err)
	}

	return program, nil

}

func runEbpfLoop(program *ebpf.RunningProgram, outputFormatter Formatter, ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			slog.Info("exiting application...")
			return
		case invocation, ok := <-program.FunctionInvocations:
			if !ok {
				slog.Info("function invocation closed")
				return
			}
			fmt.Println(outputFormatter(invocation)) // TODO add logger instead of fmt.Println

		}
	}

}
