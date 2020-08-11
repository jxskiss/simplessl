package main

import (
	"log"
	"net/http"
	"os"
	"time"
)

// TODO: leveled messages

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

func flushLogs() {
	_ = os.Stdout.Sync()
	_ = os.Stderr.Sync()
}
