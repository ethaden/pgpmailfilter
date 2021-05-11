package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ethaden/pgpmailfilter/pkg/pgpmailfilterlib"
)

var flagHelp bool
var flagInputFile string
var flagOutputFile string

func init() {
	flag.BoolVar(&flagHelp, "h", false, "Show help")
	flag.StringVar(&flagInputFile, "i", "", "input file to read. Default: read from standard input")
	flag.StringVar(&flagOutputFile, "o", "", "output file to write. Default: write to standard output")
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: pgpmailfilter [-h] [-i <input file>] [-o <output file>\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	flag.Parse()
	if flagHelp {
		flag.Usage()
		os.Exit(0)
	}
	pgpmailfilterlib.HandleMail(flagInputFile, flagOutputFile)
}
