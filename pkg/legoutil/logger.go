package legoutil

import (
	"strings"

	legolog "github.com/go-acme/lego/v4/log"
	"github.com/jxskiss/gopkg/v2/zlog"
	"go.uber.org/zap"
)

var _ legolog.StdLogger = &wrapLogger{}

func NewLogger() *wrapLogger {
	l := zlog.L().Named("lego")
	skip2 := l.WithOptions(zap.AddCallerSkip(2)).Sugar()
	skip3 := l.WithOptions(zap.AddCallerSkip(3)).Sugar()
	return &wrapLogger{
		skip2: skip2,
		skip3: skip3,
	}
}

type wrapLogger struct {
	skip2 *zap.SugaredLogger
	skip3 *zap.SugaredLogger
}

func (w *wrapLogger) Fatal(args ...interface{}) {
	w.skip2.Fatal(args...)
}

func (w *wrapLogger) Fatalln(args ...interface{}) {
	w.skip2.Fatal(args...)
}

func (w *wrapLogger) Fatalf(format string, args ...interface{}) {
	w.skip2.Fatalf(format, args...)
}

func (w *wrapLogger) Print(args ...interface{}) {
	w.skip2.Info(args...)
}

func (w *wrapLogger) Println(args ...interface{}) {
	w.skip2.Info(args...)
}

func (w *wrapLogger) Printf(format string, args ...interface{}) {
	if strings.HasPrefix(format, "[INFO] ") {
		w.skip3.Infof(format[7:], args...)
		return
	}
	if strings.HasPrefix(format, "[WARN] ") {
		w.skip3.Warnf(format[7:], args...)
		return
	}
	w.skip2.Infof(format, args...)
}
