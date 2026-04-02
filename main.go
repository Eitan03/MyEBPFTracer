package main

import (
	"MyGoTracer/cmd"
	"MyGoTracer/internal/elfLoader"
	"flag"
	"fmt"
	"log/slog"
	"os"
)

func main() {

	slog.SetLogLoggerLevel(slog.LevelDebug)

	// TODO filter by package

	filePath := flag.String("file", "", "a path to the executable go file of the tracee")
	packageName := flag.String("package", "", "a package to filter the traced function by")
	format := flag.String("format", "text", "the output format (text/json)")
	pid := flag.Uint("pid", 0, "the pid of the specified program to follow, 0 if all instances") // TODO check 0 works

	flag.Parse()

	if *filePath == "" {
		fmt.Println("Error! file argument must be given")
		flag.Usage()
		os.Exit(2)

	}

	filter := elfLoader.FunctionFilter{}
	if *packageName != "" {
		filter.Package = packageName
	}

	cmd.Run(*filePath, uint32(*pid), filter, *format)
}
