package logship

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"time"
)

// stdoutSink writes one compact JSON line per entry to a writer (os.Stdout by
// default). It is the zero-dependency debug/k8s path: a container log collector
// ships the lines. Reserved attributes are already stripped by the pipeline; the
// `source` field is authoritative.
type stdoutSink struct {
	enc *json.Encoder
	w   io.Writer
}

// stdoutLine is the on-the-wire shape of one stdout entry. Field order is stable
// for readability; encoding/json omits empty optional fields.
type stdoutLine struct {
	Timestamp  time.Time         `json:"timestamp"`
	Source     string            `json:"source"`
	Severity   string            `json:"severity"`
	Body       string            `json:"body"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

func newStdoutSink() *stdoutSink {
	return newStdoutSinkTo(os.Stdout)
}

func newStdoutSinkTo(w io.Writer) *stdoutSink {
	return &stdoutSink{enc: json.NewEncoder(w), w: w}
}

func (s *stdoutSink) Emit(_ context.Context, batch []Entry) error {
	for _, e := range batch {
		ts := e.Record.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		line := stdoutLine{
			Timestamp:  ts.UTC(),
			Source:     e.Source,
			Severity:   e.Record.Severity.String(),
			Body:       e.Record.Body,
			Attributes: e.Record.Attributes,
		}
		if err := s.enc.Encode(line); err != nil {
			return err
		}
	}
	return nil
}

func (s *stdoutSink) Shutdown(_ context.Context) error {
	if f, ok := s.w.(*os.File); ok {
		return f.Sync()
	}
	return nil
}

// String renders a Severity as a stable lowercase token for the stdout sink.
func (sv Severity) String() string {
	switch sv {
	case SeverityTrace:
		return "trace"
	case SeverityDebug:
		return "debug"
	case SeverityWarn:
		return "warn"
	case SeverityError:
		return "error"
	case SeverityFatal:
		return "fatal"
	case SeverityInfo:
		return "info"
	default:
		return "info"
	}
}
