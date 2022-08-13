package telegram

//
// WebHTTPS
//
// This code was generated by `boilerplate' using
// the https template.
//

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/ooni/probe-cli/v3/internal/atomicx"
	"github.com/ooni/probe-cli/v3/internal/measurexlite"
	"github.com/ooni/probe-cli/v3/internal/model"
	"github.com/ooni/probe-cli/v3/internal/netxlite"
)

// Measures Telegram Web using HTTPS.
//
// The zero value of this structure IS NOT valid and you MUST initialize
// all the fields marked as MANDATORY before using this structure.
type WebHTTPS struct {
	// Address is the MANDATORY address to connect to.
	Address string

	// IDGenerator is the MANDATORY atomic int64 to generate task IDs.
	IDGenerator *atomicx.Int64

	// Logger is the MANDATORY logger to use.
	Logger model.Logger

	// TestKeys is MANDATORY and contains the TestKeys.
	TestKeys *TestKeys

	// ZeroTime is the MANDATORY measurement's zero time.
	ZeroTime time.Time

	// WaitGroup is the MANDATORY wait group this task belongs to.
	WaitGroup *sync.WaitGroup

	// ALPN is the OPTIONAL ALPN to use.
	ALPN []string

	// SNI is the OPTIONAL SNI to use.
	SNI string

	// HostHeader is the OPTIONAL host header to use.
	HostHeader string

	// URLPath is the OPTIONAL URL path.
	URLPath string

	// URLRawQuery is the OPTIONAL URL raw query.
	URLRawQuery string
}

// Start starts this task in a background goroutine.
func (t *WebHTTPS) Start(ctx context.Context) {
	t.WaitGroup.Add(1)
	index := t.IDGenerator.Add(1)
	go func() {
		defer t.WaitGroup.Done() // synchronize with the parent
		t.Run(ctx, index)
	}()
}

// Run runs this task in the current goroutine.
func (t *WebHTTPS) Run(parentCtx context.Context, index int64) {
	// create trace
	trace := measurexlite.NewTrace(index, t.ZeroTime)

	// start the operation logger
	ol := measurexlite.NewOperationLogger(t.Logger, "WebHTTPS#%d: %s", index, t.Address)

	// perform the TCP connect
	const tcpTimeout = 10 * time.Second
	tcpCtx, tcpCancel := context.WithTimeout(parentCtx, tcpTimeout)
	defer tcpCancel()
	tcpDialer := trace.NewDialerWithoutResolver(t.Logger)
	tcpConn, err := tcpDialer.DialContext(tcpCtx, "tcp", t.Address)
	t.TestKeys.AppendTCPConnectResults(<-trace.TCPConnect)
	if err != nil {
		ol.Stop(err)
		return
	}
	tcpConn = trace.WrapNetConn(tcpConn)
	defer func() {
		t.TestKeys.AppendNetworkEvents(trace.NetworkEvents()...)
		tcpConn.Close()
	}()

	// perform TLS handshake
	tlsSNI, err := t.sni()
	if err != nil {
		t.TestKeys.SetFundamentalFailure(err)
		ol.Stop(err)
		return
	}
	tlsHandshaker := trace.NewTLSHandshakerStdlib(t.Logger)
	tlsConfig := &tls.Config{
		NextProtos: t.alpn(),
		RootCAs:    netxlite.NewDefaultCertPool(),
		ServerName: tlsSNI,
	}
	const tlsTimeout = 10 * time.Second
	tlsCtx, tlsCancel := context.WithTimeout(parentCtx, tlsTimeout)
	defer tlsCancel()
	tlsConn, _, err := tlsHandshaker.Handshake(tlsCtx, tcpConn, tlsConfig)
	t.TestKeys.AppendTLSHandshakes(<-trace.TLSHandshake)
	if err != nil {
		ol.Stop(err)
		return
	}
	defer tlsConn.Close()

	// create HTTP transport
	httpTransport := netxlite.NewHTTPTransport(
		t.Logger,
		netxlite.NewNullDialer(),
		// note: netxlite guarantees that here tlsConn is a netxlite.TLSConn
		netxlite.NewSingleUseTLSDialer(tlsConn.(netxlite.TLSConn)),
	)

	// create HTTP request
	const httpTimeout = 10 * time.Second
	httpCtx, httpCancel := context.WithTimeout(parentCtx, httpTimeout)
	defer httpCancel()
	httpReq, err := t.newHTTPRequest(httpCtx)
	if err != nil {
		t.TestKeys.SetFundamentalFailure(err)
		ol.Stop(err)
		return
	}

	// perform HTTP transaction
	httpResp, httpRespBody, err := t.httpTransaction(httpCtx, httpTransport, httpReq, trace)
	if err != nil {
		ol.Stop(err)
		return
	}

	// parse HTTP results
	if err := t.parseResults(httpResp, httpRespBody); err != nil {
		ol.Stop(err)
		return
	}

	// completed successfully
	ol.Stop(nil)
}

// alpn returns the user-configured ALPN or a reasonable default
func (t *WebHTTPS) alpn() []string {
	if len(t.ALPN) > 0 {
		return t.ALPN
	}
	return []string{"h2", "http/1.1"}
}

// sni returns the user-configured SNI or a reasonable default
func (t *WebHTTPS) sni() (string, error) {
	if t.SNI != "" {
		return t.SNI, nil
	}
	addr, _, err := net.SplitHostPort(t.Address)
	if err != nil {
		return "", err
	}
	return addr, nil
}

// urlHost computes the host to include into the URL
func (t *WebHTTPS) urlHost(scheme string) (string, error) {
	addr, port, err := net.SplitHostPort(t.Address)
	if err != nil {
		t.Logger.Warnf("BUG: net.SplitHostPort failed for %s: %s", t.Address, err.Error())
		return "", err
	}
	if port == "443" && scheme == "https" {
		return addr, nil
	}
	return t.Address, nil // there was no need to parse after all 😬
}

// newHTTPRequest creates a new HTTP request.
func (t *WebHTTPS) newHTTPRequest(ctx context.Context) (*http.Request, error) {
	const urlScheme = "https"
	urlHost, err := t.urlHost(urlScheme)
	if err != nil {
		return nil, err
	}
	httpURL := &url.URL{
		Scheme:   urlScheme,
		Host:     urlHost,
		Path:     t.URLPath,
		RawQuery: t.URLRawQuery,
	}
	httpReq, err := http.NewRequestWithContext(ctx, "GET", httpURL.String(), nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Host", t.HostHeader)
	httpReq.Header.Set("Accept", model.HTTPHeaderAccept)
	httpReq.Header.Set("Accept-Language", model.HTTPHeaderAcceptLanguage)
	httpReq.Header.Set("User-Agent", model.HTTPHeaderUserAgent)
	return httpReq, nil
}

// httpTransaction runs the HTTP transaction and saves the results.
func (t *WebHTTPS) httpTransaction(ctx context.Context, txp model.HTTPTransport,
	req *http.Request, trace *measurexlite.Trace) (*http.Response, []byte, error) {
	const maxbody = 1 << 22
	resp, err := txp.RoundTrip(req)
	if err != nil {
		ev := trace.NewArchivalHTTPRequestResult(txp, req, resp, maxbody, []byte{}, err)
		t.TestKeys.AppendRequests(ev)
		return resp, []byte{}, err
	}
	defer resp.Body.Close()
	reader := io.LimitReader(resp.Body, maxbody)
	body, err := netxlite.ReadAllContext(ctx, reader)
	ev := trace.NewArchivalHTTPRequestResult(txp, req, resp, maxbody, body, err)
	t.TestKeys.AppendRequests(ev)
	return resp, body, err
}

// parseResults parses the results of this sub-measurement.
func (t *WebHTTPS) parseResults(resp *http.Response, respBody []byte) error {
	if resp.StatusCode != 200 {
		log.Printf("status code: %+v", resp.StatusCode)
		return errors.New("http_request_failed")
	}
	title := []byte(`<title>Telegram Web</title>`)
	if !bytes.Contains(respBody, title) {
		return errors.New("telegram_missing_title_error")
	}
	return nil
}
