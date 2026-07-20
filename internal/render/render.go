package render

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const defaultRenderTimeout = 30 * time.Second

type Mode string

const (
	Raw       Mode = "raw"
	Kustomize Mode = "kustomize"
	Helm      Mode = "helm"
)

type Options struct {
	Mode   Mode
	Path   string
	Values []string
}

func Render(options Options) ([]byte, error) {
	if options.Path == "" {
		return nil, fmt.Errorf("render path is required")
	}
	if options.Mode == "" {
		options.Mode = Raw
	}
	path, err := filepath.Abs(options.Path)
	if err != nil {
		return nil, fmt.Errorf("resolve render path: %w", err)
	}
	switch options.Mode {
	case Raw:
		return os.ReadFile(path)
	case Kustomize:
		return run(defaultRenderTimeout, filepath.Dir(path), "kubectl", "kustomize", path)
	case Helm:
		args := []string{"template", filepath.Base(path), path, "--skip-tests"}
		for _, value := range options.Values {
			absolute, err := filepath.Abs(value)
			if err != nil {
				return nil, fmt.Errorf("resolve Helm values: %w", err)
			}
			args = append(args, "--values", absolute)
		}
		return run(defaultRenderTimeout, filepath.Dir(path), "helm", args...)
	default:
		return nil, fmt.Errorf("unsupported render mode %q", options.Mode)
	}
}

func run(timeout time.Duration, directory, name string, args ...string) ([]byte, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("%s is required for this mode: %w", name, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, path, args...)
	command.Dir = directory
	output, err := command.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("%s timed out after %s", name, timeout)
	}
	if err != nil {
		return nil, fmt.Errorf("%s failed: %w: %s", name, err, string(output))
	}
	return output, nil
}
