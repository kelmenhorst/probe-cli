package ntelegram

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/apex/log"
	"github.com/google/gopacket/layers"
	"github.com/ooni/netem"
	"github.com/ooni/probe-cli/v3/internal/legacy/mockable"
	"github.com/ooni/probe-cli/v3/internal/model"
	"github.com/ooni/probe-cli/v3/internal/netemx"
	"github.com/ooni/probe-cli/v3/internal/runtimex"
)

// The netemx environment design is based on netemx_test.

// Environment is the [netem] QA environment we use in this package.
type Environment struct {
	// clientStack is the client stack to use.
	clientStack *netem.UNetStack

	// dnsServer is the DNS server.
	dnsServer *netem.DNSServer

	// dpi refers to the [netem.DPIEngine] we're using
	dpi *netem.DPIEngine

	// httpsServer is the HTTPS server.
	httpsServers []*http.Server

	// topology is the topology we're using
	topology *netem.StarTopology
}

// NewEnvironment creates a new QA environment. This function
// calls [runtimex.PanicOnError] in case of failure.
func NewEnvironment(dnsConfig *netem.DNSConfig) *Environment {
	e := &Environment{}

	// create a new star topology
	e.topology = runtimex.Try1(netem.NewStarTopology(model.DiscardLogger))

	// create server stack
	//
	// note: because the stack is created using topology.AddHost, we don't
	// need to call Close when done using it, since the topology will do that
	// for us when we call the topology's Close method.
	dnsServerStack := runtimex.Try1(e.topology.AddHost(
		"1.2.3.4", // server IP address
		"0.0.0.0", // default resolver address
		&netem.LinkConfig{},
	))

	if dnsConfig == nil {
		// create configuration for DNS server
		dnsConfig = netem.NewDNSConfig()
		dnsConfig.AddRecord(
			"web.telegram.org",
			"web.telegram.org", // CNAME
			"149.154.167.99",
		)
	}

	// create DNS server using the dnsServerStack
	e.dnsServer = runtimex.Try1(netem.NewDNSServer(
		model.DiscardLogger,
		dnsServerStack,
		"1.2.3.4",
		dnsConfig,
	))

	// create the Telegram Web server stack
	webServerStack := runtimex.Try1(e.topology.AddHost(
		"149.154.167.99", // server IP address
		"0.0.0.0",        // default resolver address
		&netem.LinkConfig{},
	))

	// create HTTPS server instance on port 443 at the webServerStack
	webListener := runtimex.Try1(webServerStack.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.IPv4(149, 154, 167, 99),
		Port: 443,
		Zone: "",
	}))
	webServer := &http.Server{
		TLSConfig: webServerStack.ServerTLSConfig(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`hello, world`))
		}),
	}
	e.httpsServers = append(e.httpsServers, webServer)
	// run Telegram Web server
	go webServer.ServeTLS(webListener, "", "")

	for _, dc := range datacenters {
		// for each telegram endpoint, we create a server stack
		httpServerStack := runtimex.Try1(e.topology.AddHost(
			dc,        // server IP address
			"0.0.0.0", // default resolver address
			&netem.LinkConfig{},
		))
		// on each server stack we create two TCP servers -- on port 443 and 80
		for _, port := range []int{443, 80} {
			tcpListener := runtimex.Try1(httpServerStack.ListenTCP("tcp", &net.TCPAddr{
				IP:   net.ParseIP(dc),
				Port: port,
				Zone: "",
			}))
			httpServer := &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Write([]byte(`hello, world`))
				}),
			}
			e.httpsServers = append(e.httpsServers, httpServer)
			// run TCP server
			go httpServer.Serve(tcpListener)
		}
	}

	// create a DPIEngine for implementing censorship
	e.dpi = netem.NewDPIEngine(model.DiscardLogger)

	// create client stack
	//
	// note: because the stack is created using topology.AddHost, we don't
	// need to call Close when done using it, since the topology will do that
	// for us when we call the topology's Close method.
	e.clientStack = runtimex.Try1(e.topology.AddHost(
		"10.0.0.14", // client IP address
		"1.2.3.4",   // default resolver address
		&netem.LinkConfig{
			DPIEngine: e.dpi,
		},
	))

	return e
}

// DPIEngine returns the [netem.DPIEngine] we're using on the
// link between the client stack and the router. You can safely
// add new DPI rules from concurrent goroutines at any time.
func (e *Environment) DPIEngine() *netem.DPIEngine {
	return e.dpi
}

// Do executes the given function such that [netxlite] code uses the
// underlying clientStack rather than ordinary networking code.
func (e *Environment) Do(function func()) {
	netemx.WithCustomTProxy(e.clientStack, function)
}

// Close closes all the resources used by [Environment].
func (e *Environment) Close() error {
	e.dnsServer.Close()
	for _, s := range e.httpsServers {
		s.Close()
	}
	e.topology.Close()
	return nil
}

func newsession() model.ExperimentSession {
	return &mockable.Session{MockableLogger: log.Log}
}

func TestNewExperimentMeasurer(t *testing.T) {
	measurer := NewExperimentMeasurer(Config{})
	if measurer.ExperimentName() != "ntelegram" {
		t.Fatal("unexpected name")
	}
	if measurer.ExperimentVersion() != "0.1.0" {
		t.Fatal("unexpected version")
	}
}

func TestSummaryKeysInvalidType(t *testing.T) {
	measurement := new(model.Measurement)
	m := &Measurer{}
	_, err := m.GetSummaryKeys(measurement)
	if err.Error() != "invalid test keys type" {
		t.Fatal("not the error we expected")
	}
}

func TestIntegrationMeasurer(t *testing.T) {
	t.Run("Test Measurer without DPI: expect success", func(t *testing.T) {
		// create a new test environment
		env := NewEnvironment(nil)
		defer env.Close()
		env.Do(func() {
			measurer := NewExperimentMeasurer(Config{})
			measurement := &model.Measurement{}
			args := &model.ExperimentArgs{
				Callbacks:   model.NewPrinterCallbacks(log.Log),
				Measurement: measurement,
				Session:     newsession(),
			}
			err := measurer.Run(context.Background(), args)
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}
			tk, _ := (measurement.TestKeys).(*TestKeys)
			if tk.TelegramWebFailure != nil {
				t.Fatalf("Unexpected Telegram Web failure %s", *tk.TelegramWebFailure)
			}
			if tk.TelegramHTTPBlocking {
				t.Fatalf("Unexpected HTTP blocking")
			}
			if tk.TelegramTCPBlocking {
				t.Fatal("Unexpected TCP blocking")
			}
			sk, err := measurer.GetSummaryKeys(measurement)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := sk.(SummaryKeys); !ok {
				t.Fatal("invalid type for summary keys")
			}
		})
	})

	t.Run("Test Measurer with poisoned DNS: expect TelegramWebFailure", func(t *testing.T) {
		// create a new test environment with bogon DNS
		dnsConfig := netem.NewDNSConfig()
		dnsConfig.AddRecord(
			"web.telegram.org",
			"web.telegram.org", // CNAME
			"a.b.c.d",          // bogon
		)
		env := NewEnvironment(dnsConfig)
		defer env.Close()
		env.Do(func() {
			measurer := NewExperimentMeasurer(Config{})
			measurement := &model.Measurement{}
			args := &model.ExperimentArgs{
				Callbacks:   model.NewPrinterCallbacks(log.Log),
				Measurement: measurement,
				Session:     newsession(),
			}
			err := measurer.Run(context.Background(), args)
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}
			tk, _ := (measurement.TestKeys).(*TestKeys)
			if tk.TelegramWebFailure == nil {
				t.Fatalf("Expected Web Failure but got none")
			}
			if tk.TelegramHTTPBlocking {
				t.Fatal("Unexpected HTTP blocking")
			}
			if tk.TelegramTCPBlocking {
				t.Fatal("Unexpected TCP blocking")
			}
		})
	})

	t.Run("Test Measurer with DPI that drops TCP traffic towards telegram endpoint: expect Telegram(HTTP|TCP)Blocking", func(t *testing.T) {
		// overwrite global datacenters, otherwise the test times out because there are too many endpoints
		orig := datacenters
		datacenters = []string{
			"149.154.175.50",
		}
		// create a new test environment
		env := NewEnvironment(nil)
		defer env.Close()
		// create DPI that drops traffic for datacenter endpoints on ports 443 and 80
		dpi := env.DPIEngine()
		for _, dc := range datacenters {
			dpi.AddRule(&netem.DPIDropTrafficForServerEndpoint{
				Logger:          model.DiscardLogger,
				ServerIPAddress: dc,
				ServerPort:      80,
				ServerProtocol:  layers.IPProtocolTCP,
			})
			dpi.AddRule(&netem.DPIDropTrafficForServerEndpoint{
				Logger:          model.DiscardLogger,
				ServerIPAddress: dc,
				ServerPort:      443,
				ServerProtocol:  layers.IPProtocolTCP,
			})
		}
		env.Do(func() {
			measurer := NewExperimentMeasurer(Config{})
			measurement := &model.Measurement{}
			args := &model.ExperimentArgs{
				Callbacks:   model.NewPrinterCallbacks(log.Log),
				Measurement: measurement,
				Session:     newsession(),
			}
			err := measurer.Run(context.Background(), args)
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}
			tk, _ := (measurement.TestKeys).(*TestKeys)
			if tk.TelegramWebFailure != nil {
				t.Fatalf("Unexpected Telegram Web failure %s", *tk.TelegramWebFailure)
			}
			if !tk.TelegramHTTPBlocking {
				t.Fatal("Expected HTTP blocking but got none")
			}
			if !tk.TelegramTCPBlocking {
				t.Fatal("Expected TCP blocking but got none")
			}
		})
		datacenters = orig
	})

	t.Run("Test Measurer with DPI that drops TLS traffic with SNI = web.telegram.org: expect TelegramWebFailure", func(t *testing.T) {
		// create a new test environment
		env := NewEnvironment(nil)
		defer env.Close()
		// create DPI that drops TLS packets with SNI = web.telegram.org
		dpi := env.DPIEngine()
		dpi.AddRule(&netem.DPIResetTrafficForTLSSNI{
			Logger: model.DiscardLogger,
			SNI:    "web.telegram.org",
		})
		env.Do(func() {
			measurer := NewExperimentMeasurer(Config{})
			measurement := &model.Measurement{}
			args := &model.ExperimentArgs{
				Callbacks:   model.NewPrinterCallbacks(log.Log),
				Measurement: measurement,
				Session:     newsession(),
			}
			err := measurer.Run(context.Background(), args)
			if err != nil {
				t.Fatalf("Unexpected error: %s", err)
			}
			tk, _ := (measurement.TestKeys).(*TestKeys)
			if tk.TelegramWebFailure == nil {
				t.Fatalf("Expected Web Failure but got none")
			}
			if tk.TelegramHTTPBlocking {
				t.Fatal("Unexpected HTTP blocking")
			}
			if tk.TelegramTCPBlocking {
				t.Fatal("Unexpected TCP blocking")
			}
		})
	})
}
