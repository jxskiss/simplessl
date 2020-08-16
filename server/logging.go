package server

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

var accessLogger = log.New(os.Stdout, "", 0)

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		lrw := &loggingResponseWriter{w, http.StatusOK}
		defer func(start time.Time) {
			// [yyyymmdd hhmmss Addr] Status Method URI Duration
			const LogFormat = "[%s %s] %d %s %s %s\n"
			now := time.Now().UTC()
			logTime := now.Format("20060102 15:04:05")
			accessLogger.Printf(LogFormat, logTime, req.RemoteAddr, lrw.statusCode, req.Method, req.RequestURI, now.Sub(start))
		}(time.Now())
		next.ServeHTTP(lrw, req)
	})
}

func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Check for broken connection, as it is not really a
				// condition that warrants a panic stack trace.
				var brokenPipe = false
				if ne, ok := err.(*net.OpError); ok {
					if se, ok := ne.Err.(*os.SyscallError); ok {
						lowerErr := strings.ToLower(se.Error())
						if strings.Contains(lowerErr, "broken pipe") ||
							strings.Contains(lowerErr, "connection reset by peer") {
							brokenPipe = true
						}
					}
				}
				if brokenPipe {
					return
				}
				loc := identifyPanic()
				stack := debug.Stack()
				log.Printf("[ERROR] catch panic: *** %s ***\n%s %s\n%s",
					loc, req.Method, req.URL.RequestURI(), stack)
				w.WriteHeader(500)
			}
		}()
		next.ServeHTTP(w, req)
	})
}

func identifyPanic() string {
	var name, file string
	var line int
	var pc [16]uintptr

	n := runtime.Callers(3, pc[:])
	for _, pc := range pc[:n] {
		fn := runtime.FuncForPC(pc)
		if fn == nil {
			continue
		}
		file, line = fn.FileLine(pc)
		name = fn.Name()
		if !strings.HasPrefix(name, "runtime.") {
			break
		}
	}
	switch {
	case name != "":
		return fmt.Sprintf("%v:%v", name, line)
	case file != "":
		return fmt.Sprintf("%v:%v", file, line)
	}

	return fmt.Sprintf("pc:%x", pc)
}

func FlushLogs() {
	_ = os.Stdout.Sync()
	_ = os.Stderr.Sync()
}
