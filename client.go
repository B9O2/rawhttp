package rawhttp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/B9O2/rawhttp/client"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/retryablehttp-go"

	urlutil "github.com/projectdiscovery/utils/url"
)

// Client is a client for making raw http requests with go
type Client struct {
	dialer         Dialer
	lam            *LocalAddrManager
	DefaultOptions Options
}

// NewClient creates a new rawhttp client with provided options
func NewClient(options Options) *Client {
	client := &Client{
		dialer:         new(dialer),
		lam:            NewLocalAddrManager(),
		DefaultOptions: options,
	}
	/*
		if options.FastDialerOpts == nil {
			var err error
			options.FastDialerOpts, err = fastdialer.NewDialer(fastdialer.DefaultOptions)
			if err != nil {
				gologger.Error().Msgf("Could not create fast dialer: %s\n", err)
			}
		}
	*/
	return client
}

// Head makes a HEAD request to a given URL
func (c *Client) Head(url string) (*http.Response, error) {
	return c.DoRaw("HEAD", url, "", client.HTTP_1_1, nil, nil)
}

// Get makes a GET request to a given URL
func (c *Client) Get(url string) (*http.Response, error) {
	return c.DoRaw("GET", url, "", client.HTTP_1_1, nil, nil)
}

// Post makes a POST request to a given URL
func (c *Client) Post(url string, mimetype string, body io.Reader) (*http.Response, error) {
	headers := make(map[string][]string)
	headers["Content-Type"] = []string{mimetype}
	return c.DoRaw("POST", url, "", client.HTTP_1_1, headers, body)
}

// Do sends a http request and returns a response
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	method := req.Method
	headers := req.Header
	url := req.URL.String()
	body := req.Body
	version := client.Version{
		Major: req.ProtoMajor,
		Minor: req.ProtoMinor,
	}

	return c.DoRaw(method, url, "", version, headers, body)
}

// Dor sends a retryablehttp request and returns the response
func (c *Client) Dor(req *retryablehttp.Request) (*http.Response, error) {
	method := req.Method
	headers := req.Header
	url := req.URL.String()
	body := req.Body
	version := client.Version{
		Major: req.ProtoMajor,
		Minor: req.ProtoMinor,
	}

	return c.DoRaw(method, url, "", version, headers, body)
}

// DoRaw does a raw request with some configuration
func (c *Client) DoRaw(method, url, uripath string, version client.Version, headers map[string][]string, body io.Reader) (*http.Response, error) {
	redirectstatus := &RedirectStatus{
		FollowRedirects: true,
		MaxRedirects:    c.DefaultOptions.MaxRedirects,
	}
	return c.do(method, url, uripath, version, headers, body, redirectstatus, c.DefaultOptions)
}

// DoRawWithOptions performs a raw request with additional options
func (c *Client) DoRawWithOptions(method, url, uripath string, version client.Version, headers map[string][]string, body io.Reader, options Options) (*http.Response, error) {
	redirectstatus := &RedirectStatus{
		FollowRedirects: options.FollowRedirects,
		MaxRedirects:    c.DefaultOptions.MaxRedirects,
	}
	return c.do(method, url, uripath, version, headers, body, redirectstatus, options)
}

// Close closes client and any resources it holds
func (c *Client) Close() {

}

func (c *Client) getConn(protocol, host string, options Options, fd *fastdialer.Dialer) (Conn, error) {

	if options.Proxy != "" {
		return c.dialer.DialWithProxy(protocol, host, options.Proxy, options.ProxyDialTimeout, options, fd)
	}

	var conn Conn
	var err error
	if options.Timeout > 0 {
		conn, err = c.dialer.DialTimeout(protocol, host, options.Timeout, options, fd)
	} else {
		conn, err = c.dialer.Dial(protocol, host, options, fd)
	}

	return conn, err
}

func (c *Client) do(method, url, uripath string, version client.Version, headers map[string][]string, body io.Reader, redirectstatus *RedirectStatus, options Options) (_ *http.Response, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("rawhttp panic:" + fmt.Sprint(r))
			return
		}
		if err != nil {
			err = errors.New("rawhttp error:" + err.Error())
		}
	}()

	protocol := "http"
	if strings.HasPrefix(strings.ToLower(url), "https://") {
		protocol = "https"
	}

	if headers == nil {
		headers = make(map[string][]string)
	}
	u, err := urlutil.ParseURL(url, true)
	if err != nil {
		return nil, err
	}

	host := u.Host

	if options.AutomaticHostHeader {
		// add automatic space
		headers["Host"] = []string{fmt.Sprintf(" %s", host)}
	}

	if !strings.Contains(host, ":") {
		if protocol == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	// standard path
	path := u.Path
	if path == "" {
		path = "/"
	}
	if !u.Params.IsEmpty() {
		path += "?" + u.Params.Encode()
	}
	// override if custom one is specified
	if uripath != "" {
		path = uripath
	}

	if strings.HasPrefix(url, "https://") {
		protocol = "https"
	}

	req := toRequest(method, path, nil, version, headers, body, &options)
	req.AutomaticContentLength = options.AutomaticContentLength
	req.AutomaticHost = options.AutomaticHostHeader

	//Fastdialer
	fdopts := fastdialer.DefaultOptions
	fdopts.Dialer = &net.Dialer{
		Timeout:  options.Timeout,
		Resolver: net.DefaultResolver,
	}
	fdopts.Dialer.Control = options.Control

	//Conn
	var fd *fastdialer.Dialer
	var connection Conn
	var localAddr *net.TCPAddr
	if options.LocalAddr == nil {
		var netInterfaces []net.Interface
		if len(options.NetInterface) > 0 {
			inter, err := net.InterfaceByName(options.NetInterface)
			if err != nil {
				return nil, err
			}
			netInterfaces = []net.Interface{
				*inter,
			}
		} else {
			netInterfaces, err = net.Interfaces()
			if err != nil {
				return nil, err
			}
		}

		for _, inter := range netInterfaces {
			localAddr, err = c.lam.GetLocalAddr(inter.Name)
			if err == nil {
				fdopts.Dialer.LocalAddr = localAddr
				fd, err = fastdialer.NewDialer(fdopts)
				if err != nil {
					return nil, err
				}
				connection, err = c.getConn(protocol, host, options, fd)
				if err == nil {
					break
				}
			}
		}

	} else {
		fd, err = fastdialer.NewDialer(fdopts)
		if err != nil {
			return nil, err
		}
		connection, err = c.getConn(protocol, host, options, fd)
	}

	if err != nil {
		return nil, err
	}

	//Middlewares
	for _, m := range options.Middlewares {
		func() {
			defer func() {
				if r := recover(); r != nil {
					err = errors.New("Middleware Panic:" + fmt.Sprint(r))
				}
			}()
			m.Handle(options, fdopts, req)
		}()
	}
	if err != nil {
		return nil, err
	}

	// set timeout if any
	if options.Timeout > 0 {
		t := time.Now().Add(options.Timeout)
		if connection != nil {
			err = connection.SetDeadline(t)
			if err != nil {
				return nil, err
			}
		}

	}

	if err = connection.WriteRequest(req); err != nil {
		return nil, err
	}
	resp, err := connection.ReadResponse(options.ForceReadAllBody)
	if err != nil {
		return nil, err
	}

	r, err := toHTTPResponse(connection, resp)
	if err != nil {
		return nil, err
	}

	if resp.Status.IsRedirect() && redirectstatus.FollowRedirects && redirectstatus.Current <= redirectstatus.MaxRedirects {
		// consume the response body
		_, err := io.Copy(io.Discard, r.Body)
		if err := firstErr(err, r.Body.Close()); err != nil {
			return nil, err
		}
		loc := headerValue(r.Header, "Location")
		if !strings.HasPrefix(loc, "http") {
			if !strings.HasPrefix(loc, "/") {
				loc = "/" + loc
			}
			loc = fmt.Sprintf("%s://%s%s", protocol, host, loc)
		}
		redirectstatus.Current++
		return c.do(method, loc, uripath, version, headers, body, redirectstatus, options)
	}
	return r, err
}

// RedirectStatus is the current redirect status for the request
type RedirectStatus struct {
	FollowRedirects bool
	MaxRedirects    int
	Current         int
}
