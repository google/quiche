// depstool is a command-line tool for manipulating QUICHE WORKSPACE.bazel file.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/bazelbuild/buildtools/build"
	"quiche.googlesource.com/quiche/depstool/deps"
)

func validate(path string, contents []byte) {
	file, err := build.ParseWorkspace(path, contents)
	if err != nil {
		log.Fatalf("Failed to parse the WORKSPACE.bazel file: %v", err)
	}

	success := true
	for _, stmt := range file.Stmt {
		rule, ok := deps.HTTPArchiveRule(stmt)
		if !ok {
			// Skip unrelated rules
			continue
		}
		if _, err := deps.ParseHTTPArchiveRule(rule); err != nil {
			log.Printf("Failed to parse http_archive in %s on the line %d, issue: %v", path, rule.Pos.Line, err)
			success = false
		}
	}
	if !success {
		os.Exit(1)
	}
	log.Printf("All http_archive rules have been validated successfully")
	os.Exit(0)
}

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), `
usage: depstool [WORKSPACE file] [subcommand]

Available subcommands:
    validate   Validates that the WORKSPACE file is parsable
`)
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flag.Parse()
	path := flag.Arg(0)
	if path == "" {
		usage()
		os.Exit(1)
	}
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read WORKSPACE.bazel file: %v", err)
	}

	subcommand := flag.Arg(1)
	switch subcommand {
	case "validate":
		validate(path, contents)
	default:
		log.Fatalf("Unknown command: %s", subcommand)
	}
}
