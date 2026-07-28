package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/heyimusa/kube-blast-radius/internal/manifest"
	"github.com/heyimusa/kube-blast-radius/internal/render"
	"github.com/heyimusa/kube-blast-radius/internal/report"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "diff" {
		fmt.Fprintln(os.Stderr, "usage: kube-blast-radius diff --before PATH --after PATH [--mode raw|kustomize|helm] [--format text|json|sarif]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	before := fs.String("before", "", "before manifest/path")
	after := fs.String("after", "", "after manifest/path")
	mode := fs.String("mode", "raw", "raw, kustomize, or helm")
	format := fs.String("format", "text", "text, json, or sarif")
	beforeValues := fs.String("before-values", "", "Helm values file for before render")
	afterValues := fs.String("after-values", "", "Helm values file for after render")
	if err := fs.Parse(os.Args[2:]); err != nil || *before == "" || *after == "" || (*format != "text" && *format != "json" && *format != "sarif") {
		fs.Usage()
		os.Exit(2)
	}
	old, err := render.Render(render.Options{Mode: render.Mode(*mode), Path: *before, Values: optionalValue(*beforeValues)})
	if err != nil {
		fail(err)
	}
	next, err := render.Render(render.Options{Mode: render.Mode(*mode), Path: *after, Values: optionalValue(*afterValues)})
	if err != nil {
		fail(err)
	}
	findings, err := manifest.Analyze(old, next)
	if err != nil {
		fail(err)
	}
	if *format == "json" {
		out, err := report.JSON(findings)
		if err != nil {
			fail(err)
		}
		fmt.Println(string(out))
	} else if *format == "sarif" {
		out, err := report.SARIF(findings)
		if err != nil {
			fail(err)
		}
		fmt.Println(string(out))
	} else {
		fmt.Print(report.Text(findings))
	}
	for _, f := range findings {
		if f.Severity == "high" {
			os.Exit(1)
		}
	}
}
func optionalValue(value string) []string {
	if value == "" {
		return nil
	}
	return []string{value}
}
func fail(err error) { fmt.Fprintln(os.Stderr, "kube-blast-radius:", err); os.Exit(2) }
