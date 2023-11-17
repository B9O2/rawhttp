package rawhttp

import (
	"time"

	"github.com/B9O2/rawhttp/client"
	"github.com/projectdiscovery/fastdialer/fastdialer"
)

// Options contains configuration options for rawhttp client
type Options struct {
	Timeout                time.Duration
	FollowRedirects        bool
	MaxRedirects           int
	AutomaticHostHeader    bool
	AutomaticContentLength bool
	CustomHeaders          client.Headers
	ForceReadAllBody       bool // ignores content length and reads all body
	CustomRawBytes         []byte
	Proxy                  string
	ProxyDialTimeout       time.Duration
	SNI                    string

	//*
	NetInterface   string
	Middlewares    []Middleware
	FastDialerOpts *fastdialer.Options
}

// DefaultOptions is the default configuration options for the client
var DefaultOptions = &Options{
	Timeout:                30 * time.Second,
	FollowRedirects:        true,
	MaxRedirects:           10,
	AutomaticHostHeader:    true,
	AutomaticContentLength: true,
}
