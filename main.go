package main

import (
	"fmt"
	"runtime/debug"

	"github.com/jxskiss/gopkg/v2/zlog"
	"github.com/jxskiss/mcli"

	"github.com/jxskiss/simplessl/cmd"
)

const VERSION = "0.7.0-dev"

func main() {
	zlog.SetDevelopment()
	defer zlog.Sync()

	mcli.AddHelp()
	mcli.Add("run", cmd.RunServer, "Run certificate server")
	mcli.Add("generate-self-signed", cmd.GenerateSelfSignedCertificate, "Generate self-signed certificate")
	mcli.Add("self-sign ca", cmd.SelfSignCACertificate, "Generate self-signed CA certificate")
	mcli.Add("self-sign sds-server", cmd.SelfSignSDSServerCertificate, "Generate self-signed SDS server certificate")
	mcli.Add("self-sign sds-client", cmd.SelfSignSDSClientCertificate, "Generate self-signed SDS client certificate")
	mcli.Add("version", cmdPrintVersion, "Print version information")
	mcli.Run()
}

func cmdPrintVersion() {
	gitRevision := "unknown"
	buildInfo, ok := debug.ReadBuildInfo()
	if ok {
		for _, setting := range buildInfo.Settings {
			if setting.Key == "vcs.revision" {
				gitRevision = setting.Value
				if len(gitRevision) > 12 {
					gitRevision = gitRevision[:12]
				}
			}
		}
	}
	fmt.Printf("simplessl v%s-%s\n", VERSION, gitRevision)
}
