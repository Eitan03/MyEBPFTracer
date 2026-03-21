package main

import (
	"MyGoTracer/cmd/ebpf"
	elfLoader "MyGoTracer/cmd/elfLoader"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
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

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	elfFile, err := elfLoader.LoadGoFile("/mnt/goTest/helloProgram/hello")
	if err != nil {
		slog.Error(fmt.Sprintf("error extracting functions from ELF: %v", err))
		return
	}

	elfFile.Symbols = filter(elfFile.Symbols, func(s elfLoader.Symbol) bool { return strings.HasPrefix(s.Name, "main") })

	for _, s := range elfFile.Symbols {
		slog.Info(fmt.Sprintf("function name: %s, function address 0x%x", s.Name, s.Address))
	}

	program, err := ebpf.LoadElfFile(*elfFile, 10419, ctx)
	if err != nil {
		slog.Error(fmt.Sprintf("error loading ebpf file: %v", err))
		return
	}

	go func() {
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
				slog.Info(fmt.Sprintf("function %s was called from %d in address 0x%x", invocation.Name, invocation.Tid, invocation.Address))

			}
		}
	}()

	<-done
	slog.Info("exiting application...")
	cancel()
	// time.Sleep(time.Second * 10)
	runtime.Goexit()
}
