package rawhttp

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/B9O2/rawhttp/client"
	urlutil "github.com/projectdiscovery/utils/url"
)

// StatusError is a HTTP status error object
type StatusError struct {
	client.Status
}

func (s *StatusError) Error() string {
	return s.Status.String()
}

type readCloser struct {
	io.Reader
	io.Closer
}

func toRequest(method string, path string, query []string, version client.Version, headers map[string][]string, body io.Reader, options *Options) *client.Request {
	if len(options.CustomRawBytes) > 0 {
		return &client.Request{RawBytes: options.CustomRawBytes}
	}
	reqHeaders := toHeaders(headers)
	if len(options.CustomHeaders) > 0 {
		reqHeaders = options.CustomHeaders
	}

	return &client.Request{
		Method:  method,
		Path:    path,
		Query:   query,
		Version: version,
		Headers: reqHeaders,
		Body:    body,
	}
}
func toHTTPResponse(conn Conn, resp *client.Response) (*http.Response, error) {
	rheaders := fromHeaders(resp.Headers)
	r := http.Response{
		ProtoMinor:    resp.Version.Minor,
		ProtoMajor:    resp.Version.Major,
		Status:        resp.Status.String(),
		StatusCode:    resp.Status.Code,
		Header:        rheaders,
		ContentLength: resp.ContentLength(),
	}

	var err error
	rbody := resp.Body
	if headerValue(rheaders, "Content-Encoding") == "gzip" {
		rbody, err = gzip.NewReader(rbody)
		if err != nil {
			return nil, err
		}
	}
	rc := &readCloser{rbody, conn}

	r.Body = rc

	return &r, nil
}

func toHeaders(h map[string][]string) []client.Header {
	var r []client.Header
	for k, v := range h {
		for _, v := range v {
			r = append(r, client.Header{Key: k, Value: v})
		}
	}
	return r
}

func fromHeaders(h []client.Header) map[string][]string {
	if h == nil {
		return nil
	}
	var r = make(map[string][]string)
	for _, hh := range h {
		r[hh.Key] = append(r[hh.Key], hh.Value)
	}
	return r
}

func headerValue(headers map[string][]string, key string) string {
	return strings.Join(headers[key], " ")
}

func firstErr(err1, err2 error) error {
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return nil
}

// DumpRequestRaw to string
func DumpRequestRaw(method, url, uripath string, version client.Version, headers map[string][]string, body io.Reader, options *Options) ([]byte, error) {
	if len(options.CustomRawBytes) > 0 {
		return options.CustomRawBytes, nil
	}
	if headers == nil {
		headers = make(map[string][]string)
	}
	u, err := urlutil.ParseURL(url, true)
	if err != nil {
		return nil, err
	}

	// Handle only if host header is missing
	_, hasHostHeader := headers["Host"]
	if !hasHostHeader {
		host := u.Host
		headers["Host"] = []string{host}
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

	req := toRequest(method, path, nil, version, headers, body, options)
	b := strings.Builder{}

	q := strings.Join(req.Query, "&")
	if len(q) > 0 {
		q = "?" + q
	}

	b.WriteString(fmt.Sprintf("%s %s%s %s"+client.NewLine, req.Method, req.Path, q, req.Version.String()))

	for _, header := range req.Headers {
		if header.Value != "" {
			b.WriteString(fmt.Sprintf("%s: %s"+client.NewLine, header.Key, header.Value))
		} else {
			b.WriteString(fmt.Sprintf("%s"+client.NewLine, header.Key))
		}
	}

	l := req.ContentLength()
	if req.AutomaticContentLength && l >= 0 {
		b.WriteString(fmt.Sprintf("Content-Length: %d"+client.NewLine, l))
	}

	b.WriteString(client.NewLine)

	if req.Body != nil {
		var buf bytes.Buffer
		tee := io.TeeReader(req.Body, &buf)
		body, err := io.ReadAll(tee)
		if err != nil {
			return nil, err
		}
		b.Write(body)
	}

	return []byte(strings.ReplaceAll(b.String(), "\n", client.NewLine)), nil
}

func GetFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
func GetIPFromNetInterface(inter net.Interface) (string, bool) {
	if (inter.Flags & net.FlagUp) != 0 {
		addrs, _ := inter.Addrs()
		for _, address := range addrs {
			if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					return ipnet.IP.String(), true
				}
			}
		}
	}
	return "127.0.0.1", false
}

func GetLocalIP(interName string) (string, error) {

	if interName == "" {
		netInterfaces, err := net.Interfaces()
		if err != nil {
			return "127.0.0.1", err
		}
		for _, inter := range netInterfaces {
			if res, ok := GetIPFromNetInterface(inter); ok {
				return res, nil
			}
		}
	} else {
		inter, err := net.InterfaceByName(interName)
		if err != nil {
			return "127.0.0.1", err
		}
		if res, ok := GetIPFromNetInterface(*inter); ok {
			return res, nil
		}
	}

	return "127.0.0.1", errors.New("no available ip")
}

func GetLocalAddr(interName string) (*net.TCPAddr, error) {
	if port, err := GetFreePort(); err != nil {
		return nil, err
	} else {
		ip, err := GetLocalIP(interName)
		if err != nil {
			return nil, err
		}
		if addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", ip, port)); err != nil {
			return nil, err
		} else {
			return addr, nil
		}
	}
}
