package rawhttp

import "github.com/B9O2/rawhttp/client"

type Middleware interface {
	Handle(Options, *client.Request, Conn)
}
