package observability

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

// NewTraceHandler wraps a slog.Handler to inject trace_id and span_id
// attributes from the context into every log record.
func NewTraceHandler(inner slog.Handler) *TraceHandler {
	return &TraceHandler{inner: inner}
}

type TraceHandler struct {
	inner slog.Handler
}

func (h *TraceHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *TraceHandler) Handle(ctx context.Context, r slog.Record) error {
	if spanCtx := trace.SpanContextFromContext(ctx); spanCtx.IsValid() {
		r.AddAttrs(
			slog.String("trace_id", spanCtx.TraceID().String()),
			slog.String("span_id", spanCtx.SpanID().String()),
		)
	}

	return h.inner.Handle(ctx, r)
}

func (h *TraceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &TraceHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h *TraceHandler) WithGroup(name string) slog.Handler {
	return &TraceHandler{inner: h.inner.WithGroup(name)}
}
