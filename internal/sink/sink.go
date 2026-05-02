package sink

import (
	"fmt"
	"io"
	"os"

	"github.com/scuq/notrouter/internal/source"
)

type Sink interface {
	Deliver(ev source.Event) error
}

type Stdout struct {
	w io.Writer
}

func NewStdout(w io.Writer) *Stdout {
	return &Stdout{w: w}
}

func (s *Stdout) Deliver(ev source.Event) error {
	_, err := fmt.Fprintln(s.w, ev.Message)
	return err
}

type File struct {
	path string
}

func NewFile(path string) *File {
	return &File{path: path}
}

func (s *File) Deliver(ev source.Event) error {
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, ev.Message)
	return err
}
