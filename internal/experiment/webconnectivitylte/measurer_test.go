package webconnectivitylte_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"testing"

	"github.com/apex/log"
	"github.com/ooni/netem"
	"github.com/ooni/probe-cli/v3/internal/engine"
	"github.com/ooni/probe-cli/v3/internal/experiment/webconnectivitylte"
	"github.com/ooni/probe-cli/v3/internal/model"
	"github.com/ooni/probe-cli/v3/internal/netemx"
	"github.com/ooni/probe-cli/v3/internal/netxlite"
	"github.com/ooni/probe-cli/v3/internal/oohelperd"
	"github.com/ooni/probe-cli/v3/internal/runtimex"
	"golang.org/x/net/publicsuffix"
)

func newEnvironment() *netemx.QAEnv {
	// configure DoH server
	dohServer := &netemx.DoHServer{}
	dohServer.AddRecord("ams-pg-test.ooni.org", "188.166.93.143")
	dohServer.AddRecord("geoip.ubuntu.com", "185.125.188.132")
	dohServer.AddRecord("www.example.com", "93.184.216.34")
	dohServer.AddRecord("0.th.ooni.org", "104.248.30.161")
	dohServer.AddRecord("1.th.ooni.org", "104.248.30.161")
	dohServer.AddRecord("2.th.ooni.org", "104.248.30.161")
	dohServer.AddRecord("3.th.ooni.org", "104.248.30.161")

	env := netemx.NewQAEnv(
		netemx.QAEnvOptionDNSOverUDPResolvers("8.8.4.4"),
		netemx.QAEnvOptionHTTPServer("93.184.216.34", netemx.QAEnvDefaultHTTPHandler()),
		netemx.QAEnvOptionHTTPServer("104.248.30.161", nil),
		netemx.QAEnvOptionHTTPServer("104.16.248.249", dohServer),
		netemx.QAEnvOptionHTTPServer("188.166.93.143", &probeService{}),
		netemx.QAEnvOptionHTTPServer("185.125.188.132", &netemx.GeoIPLookup{}),
	)

	// create new testhelper handler using the newly created server stack
	underlyingStack := env.GetServerStack("104.248.30.161")
	helperHandler := newTestHelper(underlyingStack)
	env.AddHandler("104.248.30.161", helperHandler)

	// configure default UDP DNS server
	env.AddRecordToAllResolvers(
		"dns.quad9.net",
		"dns.quad9.net",
		"104.16.248.249",
	)
	env.AddRecordToAllResolvers(
		"mozilla.cloudflare-dns.com",
		"mozilla.cloudflare-dns.com",
		"104.16.248.249",
	)
	env.AddRecordToAllResolvers(
		"dns.nextdns.io",
		"dns.nextdns.io",
		"104.16.248.249",
	)
	env.AddRecordToAllResolvers(
		"dns.google",
		"dns.google",
		"104.16.248.249",
	)
	env.AddRecordToAllResolvers(
		"www.example.com",
		"www.example.com",
		"93.184.216.34",
	)
	return env
}

func newTestHelper(underlying netem.UnderlyingNetwork) *oohelperd.Handler {
	n := netxlite.Net{Underlying: netemx.GetCustomTProxy(underlying)}
	helperHandler := oohelperd.NewHandler()
	helperHandler.NewDialer = func(logger model.Logger) model.Dialer {
		return n.NewDialerWithResolver(logger, n.NewStdlibResolver(logger))
	}
	helperHandler.NewQUICDialer = func(logger model.Logger) model.QUICDialer {
		return n.NewQUICDialerWithResolver(
			n.NewQUICListener(),
			logger,
			n.NewStdlibResolver(logger),
		)
	}
	helperHandler.NewResolver = func(logger model.Logger) model.Resolver {
		return n.NewStdlibResolver(logger)
	}

	helperHandler.NewHTTPClient = func(logger model.Logger) model.HTTPClient {
		cookieJar, _ := cookiejar.New(&cookiejar.Options{
			PublicSuffixList: publicsuffix.List,
		})
		return &http.Client{
			Transport:     n.NewHTTPTransportStdlib(logger),
			CheckRedirect: nil,
			Jar:           cookieJar,
			Timeout:       0,
		}
	}
	helperHandler.NewHTTP3Client = func(logger model.Logger) model.HTTPClient {
		cookieJar, _ := cookiejar.New(&cookiejar.Options{
			PublicSuffixList: publicsuffix.List,
		})
		return &http.Client{
			Transport:     n.NewHTTP3TransportStdlib(logger),
			CheckRedirect: nil,
			Jar:           cookieJar,
			Timeout:       0,
		}
	}
	return helperHandler
}

func TestSuccess(t *testing.T) {
	env := newEnvironment()
	defer env.Close()
	env.Do(func() {
		measurer := webconnectivitylte.NewExperimentMeasurer(&webconnectivitylte.Config{})
		ctx := context.Background()
		// we need a real session because we need the web-connectivity helper
		// as well as the ASN database
		sess := newsession(t, true)
		measurement := &model.Measurement{Input: "https://www.example.com"}
		callbacks := model.NewPrinterCallbacks(log.Log)
		args := &model.ExperimentArgs{
			Callbacks:   callbacks,
			Measurement: measurement,
			Session:     sess,
		}
		err := measurer.Run(ctx, args)
		if err != nil {
			t.Fatal(err)
		}
		tk := measurement.TestKeys.(*webconnectivitylte.TestKeys)
		if tk.ControlFailure != nil {
			t.Fatal("unexpected control_failure", *tk.ControlFailure)
		}
		if tk.Blocking != false {
			t.Fatal("unexpected blocking detected")
		}
		if tk.Accessible != true {
			t.Fatal("unexpected accessible flag: should be accessible")
		}
	})
}

func TestDPITarget(t *testing.T) {
	env := newEnvironment()
	dpi := env.DPIEngine()
	dpi.AddRule(&netem.DPIResetTrafficForTLSSNI{
		Logger: model.DiscardLogger,
		SNI:    "www.example.com",
	})
	defer env.Close()
	env.Do(func() {
		measurer := webconnectivitylte.NewExperimentMeasurer(&webconnectivitylte.Config{})
		ctx := context.Background()
		// we need a real session because we need the web-connectivity helper
		// as well as the ASN database
		sess := newsession(t, true)
		measurement := &model.Measurement{Input: "https://www.example.com"}
		callbacks := model.NewPrinterCallbacks(log.Log)
		args := &model.ExperimentArgs{
			Callbacks:   callbacks,
			Measurement: measurement,
			Session:     sess,
		}
		err := measurer.Run(ctx, args)
		if err != nil {
			t.Fatal(err)
		}
		tk := measurement.TestKeys.(*webconnectivitylte.TestKeys)
		if tk.ControlFailure != nil {
			t.Fatal("unexpected control_failure", *tk.ControlFailure)
		}
		if tk.Blocking != "http-failure" {
			t.Fatal("unexpected blocking type")
		}
		if tk.Accessible == true {
			t.Fatal("unexpected accessible flag: should be false")
		}
	})
}

type probeService struct{}

type th struct {
	Addr string `json:"address"`
	T    string `json:"type"`
}

func (p *probeService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp := map[string][]th{
		"web-connectivity": {
			{
				Addr: "https://2.th.ooni.org",
				T:    "https",
			},
			{
				Addr: "https://3.th.ooni.org",
				T:    "https",
			},
			{
				Addr: "https://0.th.ooni.org",
				T:    "https",
			},
			{
				Addr: "https://1.th.ooni.org",
				T:    "https",
			},
		},
	}
	data, err := json.Marshal(resp)
	runtimex.PanicOnError(err, "json.Marshal failed")
	w.Header().Add("Content-Type", "application/json")
	w.Write(data)
}

func newsession(t *testing.T, lookupBackends bool) model.ExperimentSession {
	sess, err := engine.NewSession(context.Background(), engine.SessionConfig{
		AvailableProbeServices: []model.OOAPIService{{
			Address: "https://ams-pg-test.ooni.org",
			Type:    "https",
		}},
		Logger:          log.Log,
		SoftwareName:    "ooniprobe-engine",
		SoftwareVersion: "0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if lookupBackends {
		if err := sess.MaybeLookupBackends(); err != nil {
			t.Fatal(err)
		}
	}
	if err := sess.MaybeLookupLocation(); err != nil {
		t.Fatal(err)
	}
	return sess
}
