package rawhttp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/B9O2/rawhttp/client"
	"github.com/B9O2/rawhttp/proxy"
	"github.com/projectdiscovery/fastdialer/fastdialer"
)

// Dialer can dial a remote HTTP server.
type Dialer interface {
	// Dial dials a remote http server returning a Conn.
	Dial(protocol, addr string, options Options, fd *fastdialer.Dialer) (Conn, error)
	DialWithProxy(protocol, addr, proxyURL string, timeout time.Duration, options Options, fd *fastdialer.Dialer) (Conn, error)
	// Dial dials a remote http server with timeout returning a Conn.
	DialTimeout(protocol, addr string, timeout time.Duration, options Options, fd *fastdialer.Dialer) (Conn, error)
}

type dialer struct {
	sync.Mutex                   // protects following fields
	conns      map[string][]Conn // maps addr to a, possibly empty, slice of existing Conns
}

func (d *dialer) Dial(protocol, addr string, options Options, fd *fastdialer.Dialer) (Conn, error) {
	return d.dialTimeout(protocol, addr, 0, options, fd)
}

func (d *dialer) DialTimeout(protocol, addr string, timeout time.Duration, options Options, fd *fastdialer.Dialer) (Conn, error) {
	return d.dialTimeout(protocol, addr, timeout, options, fd)
}

func (d *dialer) dialTimeout(protocol, addr string, timeout time.Duration, options Options, fd *fastdialer.Dialer) (Conn, error) {
	d.Lock()
	if d.conns == nil {
		d.conns = make(map[string][]Conn)
	}
	if c, ok := d.conns[addr]; ok {
		if len(c) > 0 {
			conn := c[0]
			c[0] = c[len(c)-1]
			d.Unlock()
			return conn, nil
		}
	}
	d.Unlock()
	c, err := clientDial(protocol, addr, timeout, options, fd)
	if err != nil {
		return nil, err
	}
	return NewBaseConn(c, client.NewClient(c), d)
}

func (d *dialer) DialWithProxy(protocol, addr, proxyURL string, timeout time.Duration, options Options, fd *fastdialer.Dialer) (Conn, error) {
	var c net.Conn
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("unsupported proxy error: %w", err)
	}
	switch u.Scheme {
	case "http":
		c, err = proxy.HTTPDialer(proxyURL, timeout, fd)(addr)
	case "socks5", "socks5h": //todo: 有限支持，timeout无效
		c, err = proxy.Socks5Dialer(proxyURL, timeout)(addr)
	default:
		return nil, fmt.Errorf("unsupported proxy protocol: %s", proxyURL)
	}
	if err != nil {
		return nil, fmt.Errorf("proxy error: %w", err)
	}
	if protocol == "https" {
		if c, err = TlsHandshake(c, addr, timeout); err != nil {
			return nil, fmt.Errorf("tls handshake error: %w", err)
		}
	}

	return NewBaseConn(c, client.NewClient(c), d)
}

func clientDial(protocol, addr string, timeout time.Duration, options Options, fd *fastdialer.Dialer) (net.Conn, error) {
	var (
		ctx    context.Context
		cancel context.CancelFunc
	)
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
		defer cancel()
	} else {
		ctx = context.Background()
	}

	// http
	if protocol == "http" {
		if fd != nil {
			conn, err := fd.Dial(ctx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			return conn, nil
		} else if timeout > 0 {
			return net.DialTimeout("tcp", addr, timeout)
		}
		return net.Dial("tcp", addr)
	}

	// https
	tlsConfig := &tls.Config{InsecureSkipVerify: true, Renegotiation: tls.RenegotiateOnceAsClient}
	if options.SNI != "" {
		tlsConfig.ServerName = options.SNI
	}

	if fd == nil {
		// always use fastdialer tls dial if available
		// use net.Dialer if fastdialer tls dial is not available
		var dialer *net.Dialer
		if timeout > 0 {
			dialer = &net.Dialer{Timeout: timeout}
		} else {
			dialer = &net.Dialer{Timeout: 8 * time.Second} // should be more than enough
		}
		return tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	}

	return fd.DialTLS(ctx, "tcp", addr)
}

// TlsHandshake tls handshake on a plain connection
func TlsHandshake(conn net.Conn, addr string, timeout time.Duration) (net.Conn, error) {
	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]

	var (
		ctx    context.Context
		cancel context.CancelFunc
	)
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
		defer cancel()
	} else {
		ctx = context.Background()
	}

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         hostname,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

// Conn is an interface implemented by a connection
type Conn interface {
	client.Client
	io.Closer

	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	Release()
}

type BaseConn struct {
	net.Conn
	client.Client
	dialer *dialer
}

func (c *BaseConn) Release() {
	c.dialer.Lock()
	defer c.dialer.Unlock()
	addr := c.Conn.RemoteAddr().String()
	c.dialer.conns[addr] = append(c.dialer.conns[addr], c)
}

func NewBaseConn(conn net.Conn, c client.Client, d *dialer) (*BaseConn, error) {
	if conn == nil || c == nil {
		return nil, errors.New("conn or client is nil")
	}
	return &BaseConn{
		conn,
		c,
		d,
	}, nil
}
