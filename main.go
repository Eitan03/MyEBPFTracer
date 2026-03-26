package main

import (
	"MyGoTracer/cmd"
	"flag"
	"fmt"
	"os"
)

func main() {
	filePath := flag.String("file", "", "a path to the executable go file of the tracee")
	format := flag.String("format", "text", "the output format (text/json)")
	pid := flag.Uint("pid", 0, "the pid of the specified program to follow, 0 if all instances") // TODO check 0 works

	flag.Parse()

	if *filePath == "" {
		fmt.Println("Error! file argument must be given")
		flag.Usage()
		os.Exit(2)

	}
	cmd.Run(*filePath, uint32(*pid), *format)
}
