package cmd

import (
	elfLoader "MyGoTracer/internal/elfLoader"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func Run(filePath string, pid uint32, functionFilter elfLoader.FunctionFilter, outputFormatStr string) {

	outputFormatter := GetFormatter(outputFormatStr)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	program, err := setupEbpf(filePath, pid, functionFilter, ctx)
	if err != nil {
		slog.Error(fmt.Sprintf("error loading ebpf file: %v", err))
		return
	}

	go runEbpfLoop(program, outputFormatter, ctx)

	<-done
	slog.Info("exiting application...")
	cancel()
}
