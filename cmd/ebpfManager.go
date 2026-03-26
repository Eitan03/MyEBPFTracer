package cmd

import (
	"MyGoTracer/internal/ebpf"
	elfLoader "MyGoTracer/internal/elfLoader"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func filter[T any](ss []T, test func(T) bool) (ret []T) {
	for _, s := range ss {
		if test(s) {
			ret = append(ret, s)
		}
	}
	return
}

func setupEbpf(filePath string, pid uint32, ctx context.Context) (*ebpf.RunningProgram, error) {

	elfFile, err := elfLoader.LoadGoFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error extracting functions from ELF: %v", err)
	}

	elfFile.Symbols = filter(elfFile.Symbols, func(s elfLoader.Symbol) bool { return strings.HasPrefix(s.Name, "main") })

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

func Run(filePath string, pid uint32, outputFormatStr string) {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	outputFormatter := GetFormatter(outputFormatStr)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	program, err := setupEbpf(filePath, pid, ctx)
	if err != nil {
		slog.Error(fmt.Sprintf("error loading ebpf file: %v", err))
		return
	}

	go runEbpfLoop(program, outputFormatter, ctx)

	<-done
	slog.Info("exiting application...")
	cancel()
	// time.Sleep(time.Second * 10)
	// runtime.Goexit()
}
