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

// Emit is deliberately and explicitly ALL-OR-NOTHING (#392). Unlike OTLP there is no
// protocol here and therefore no partial-success or permanent-vs-transient signal to
// read: a failed Encode means the writer broke, which says nothing about the entries
// themselves. So the whole batch goes back for retry and nothing is ever classed
// Rejected — the resource- and protocol-aware classification is an OTLP concept and
// pretending stdout has one would invent information.
//
// Lines already written before the failure ARE on the writer, so a retry can repeat
// them. That is the accepted trade for a debug/container-log path: at-least-once with
// visible duplicates beats silently dropping the rest of the batch.
func (s *stdoutSink) Emit(_ context.Context, batch []Entry) SinkResult {
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
			return retryResult(batch, err)
		}
	}
	return ackedResult(batch)
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
