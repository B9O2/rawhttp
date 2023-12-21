package rawhttp

import (
	"github.com/B9O2/rawhttp/client"
	"github.com/projectdiscovery/fastdialer/fastdialer"
)

type Middleware interface {
	Handle(Options, fastdialer.Options, *client.Request)
}
