package nsniblocking

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/apex/log"
	"github.com/ooni/netem"
	"github.com/ooni/probe-cli/v3/internal/legacy/mockable"
	"github.com/ooni/probe-cli/v3/internal/model"
	"github.com/ooni/probe-cli/v3/internal/netemx"
	"github.com/ooni/probe-cli/v3/internal/netxlite"
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
	httpsServer *http.Server

	// topology is the topology we're using
	topology *netem.StarTopology
}

// NewEnvironment creates a new QA environment. This function
// calls [runtimex.PanicOnError] in case of failure.
func NewEnvironment(altResolver string) *Environment {
	// create a new star topology
	topology := runtimex.Try1(netem.NewStarTopology(model.DiscardLogger))
	defaultResolver := "1.2.3.4"
	resolverAddr := defaultResolver
	if altResolver != "" {
		resolverAddr = altResolver
	}

	// create server stack
	//
	// note: because the stack is created using topology.AddHost, we don't
	// need to call Close when done using it, since the topology will do that
	// for us when we call the topology's Close method.
	dnsServerStack := runtimex.Try1(topology.AddHost(
		resolverAddr,    // server IP address
		defaultResolver, // default resolver address
		&netem.LinkConfig{},
	))

	// create configuration for DNS server
	dnsConfig := netem.NewDNSConfig()
	dnsConfig.AddRecord(
		"example.org",
		"example.org", // CNAME
		"9.9.9.9",
	)

	// create DNS server using the dnsServerStack
	dnsServer := runtimex.Try1(netem.NewDNSServer(
		model.DiscardLogger,
		dnsServerStack,
		resolverAddr,
		dnsConfig,
	))

	serverStack := runtimex.Try1(topology.AddHost(
		"9.9.9.9",       // server IP address
		defaultResolver, // default resolver address
		&netem.LinkConfig{},
	))

	// create HTTPS server using the server stack
	tlsListener := runtimex.Try1(serverStack.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.IPv4(9, 9, 9, 9),
		Port: 443,
		Zone: "",
	}))
	httpsServer := &http.Server{
		TLSConfig: serverStack.ServerTLSConfig(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`hello, world`))
		}),
	}
	go httpsServer.ServeTLS(tlsListener, "", "")

	// create a DPIEngine for implementing censorship
	dpi := netem.NewDPIEngine(model.DiscardLogger)

	// create client stack
	//
	// note: because the stack is created using topology.AddHost, we don't
	// need to call Close when done using it, since the topology will do that
	// for us when we call the topology's Close method.
	clientStack := runtimex.Try1(topology.AddHost(
		"10.0.0.14",     // client IP address
		defaultResolver, // default resolver address
		&netem.LinkConfig{
			DPIEngine: dpi,
		},
	))

	return &Environment{
		clientStack: clientStack,
		dnsServer:   dnsServer,
		dpi:         dpi,
		httpsServer: httpsServer,
		topology:    topology,
	}
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
	e.httpsServer.Close()
	e.topology.Close()
	return nil
}

func newsession() model.ExperimentSession {
	return &mockable.Session{MockableLogger: log.Log}
}

func TestIntegrationMeasurer(t *testing.T) {
	t.Run("Test Measurer without DPI: expect success", func(t *testing.T) {
		env := NewEnvironment("")
		defer env.Close()
		env.Do(func() {
			measurer := NewExperimentMeasurer(Config{
				ControlSNI: "example.org",
			})
			measurement := &model.Measurement{
				Input: "google.com",
			}
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
			if tk.Result != classSuccessGotServerHello {
				t.Fatalf("Unexpected result, expected: %s, got: %s", classSuccessGotServerHello, tk.Result)
			}
			if tk.Control.Failure != nil {
				t.Fatalf("Unexpected Control Failure %s", *tk.Control.Failure)
			}
			if tk.Target.Failure != nil {
				t.Fatalf("Unexpected Target Failure %s", *tk.Target.Failure)
			}
		})
	})

	t.Run("Test Measurer with cancelled context: expect valid type of summary keys", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // immediately cancel the context
		measurer := NewExperimentMeasurer(Config{})
		measurement := &model.Measurement{
			Input: "kernel.org",
		}
		args := &model.ExperimentArgs{
			Callbacks:   model.NewPrinterCallbacks(log.Log),
			Measurement: measurement,
			Session:     newsession(),
		}
		err := measurer.Run(ctx, args)
		if err != nil {
			t.Fatal(err)
		}
		tk := measurement.TestKeys.(*TestKeys)
		if tk.Result != classAnomalyTestHelperUnreachable {
			t.Fatalf("Unexpected result, expected: %s, got: %s", classAnomalyTestHelperUnreachable, tk.Result)
		}
		sk, err := measurer.GetSummaryKeys(measurement)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := sk.(SummaryKeys); !ok {
			t.Fatal("invalid type for summary keys")
		}
	})

	t.Run("Test Measurer with cached entry: expect interrupted failure", func(t *testing.T) {
		env := NewEnvironment("")
		defer env.Close()
		env.Do(func() {
			cache := make(map[string]Subresult)
			s := netxlite.FailureInterrupted
			testsni := "google.com"
			thaddr := "example.org:443"
			cache[testsni+thaddr] = Subresult{
				Failure:   &s,
				THAddress: thaddr,
				SNI:       testsni,
			}
			measurer := NewExperimentMeasurer(Config{
				ControlSNI: "example.org",
			})
			measurer.(*Measurer).cache = cache
			measurement := &model.Measurement{
				Input: model.MeasurementTarget(testsni),
			}
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
			if tk.Result != classAnomalyUnexpectedFailure {
				t.Fatalf("Unexpected result, expected: %s, got: %s", classAnomalyUnexpectedFailure, tk.Result)
			}
			if tk.Control.Failure != nil {
				t.Fatalf("Unexpected Control Failure %s", *tk.Control.Failure)
			}
			if tk.Target.Failure == nil {
				t.Fatalf("Expected Target Failure but got none")
			}
			if *tk.Target.Failure != netxlite.FailureInterrupted {
				t.Fatalf("Unexpected Target Failure, expected: %s, got: %s", netxlite.FailureInterrupted, *tk.Target.Failure)
			}
		})
	})

	t.Run("Test Measurer with alternative UDP resolver, without DPI: expect success", func(t *testing.T) {
		env := NewEnvironment("1.1.1.1")
		defer env.Close()
		env.Do(func() {
			measurer := NewExperimentMeasurer(Config{
				ControlSNI:  "example.org",
				ResolverURL: "1.1.1.1:53",
			})
			measurement := &model.Measurement{
				Input: "google.com",
			}
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
			if tk.Result != classSuccessGotServerHello {
				t.Fatalf("Unexpected result, expected: %s, got: %s", classSuccessGotServerHello, tk.Result)
			}
			if tk.Control.Failure != nil {
				t.Fatalf("Unexpected Control Failure %s", *tk.Control.Failure)
			}
			if tk.Target.Failure != nil {
				t.Fatalf("Unexpected Target Failure %s", *tk.Target.Failure)
			}
		})
	})

	t.Run("Test Measurer with DPI that blocks target SNI", func(t *testing.T) {
		env := NewEnvironment("")
		defer env.Close()
		dpi := env.DPIEngine()
		dpi.AddRule(&netem.DPIResetTrafficForTLSSNI{
			Logger: model.DiscardLogger,
			SNI:    "google.com",
		})
		env.Do(func() {
			measurer := NewExperimentMeasurer(Config{
				ControlSNI: "example.org",
			})
			measurement := &model.Measurement{
				Input: "google.com",
			}
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
			if tk.Result != classInterferenceReset {
				t.Fatalf("Unexpected result, expected: %s, got: %s", classInterferenceReset, tk.Result)
			}
			if tk.Control.Failure != nil {
				t.Fatalf("Unexpected Control Failure %s", *tk.Control.Failure)
			}
			if tk.Target.Failure == nil {
				t.Fatalf("Expected a Target Failure, but got none")
			}
			if *tk.Target.Failure != netxlite.FailureConnectionReset {
				t.Fatalf("Unexpected Target Failure, got: %s, expected: %s", *tk.Target.Failure, netxlite.FailureConnectionReset)
			}
		})
	})
}

func TestTestKeysClassify(t *testing.T) {
	asStringPtr := func(s string) *string {
		return &s
	}
	t.Run("with tk.Target.Failure == nil", func(t *testing.T) {
		tk := new(TestKeys)
		if tk.classify() != classSuccessGotServerHello {
			t.Fatal("unexpected result")
		}
	})
	t.Run("with tk.Target.Failure == connection_refused", func(t *testing.T) {
		tk := new(TestKeys)
		tk.Target.Failure = asStringPtr(netxlite.FailureConnectionRefused)
		if tk.classify() != classAnomalyTestHelperUnreachable {
			t.Fatal("unexpected result")
		}
	})
	t.Run("with tk.Target.Failure == dns_nxdomain_error", func(t *testing.T) {
		tk := new(TestKeys)
		tk.Target.Failure = asStringPtr(netxlite.FailureDNSNXDOMAINError)
		if tk.classify() != classAnomalyTestHelperUnreachable {
			t.Fatal("unexpected result")
		}
	})
	t.Run("with tk.Target.Failure == android_dns_cache_no_data", func(t *testing.T) {
		tk := new(TestKeys)
		tk.Target.Failure = asStringPtr(netxlite.FailureAndroidDNSCacheNoData)
		if tk.classify() != classAnomalyTestHelperUnreachable {
			t.Fatal("unexpected result")
		}
	})
	t.Run("with tk.Target.Failure == connection_reset", func(t *testing.T) {
		tk := new(TestKeys)
		tk.Target.Failure = asStringPtr(netxlite.FailureConnectionReset)
		if tk.classify() != classInterferenceReset {
			t.Fatal("unexpected result")
		}
	})
	t.Run("with tk.Target.Failure == eof_error", func(t *testing.T) {
		tk := new(TestKeys)
		tk.Target.Failure = asStringPtr(netxlite.FailureEOFError)
		if tk.classify() != classInterferenceClosed {
			t.Fatal("unexpected result")
		}
	})
	t.Run("with tk.Target.Failure == ssl_invalid_hostname", func(t *testing.T) {
		tk := new(TestKeys)
		tk.Target.Failure = asStringPtr(netxlite.FailureSSLInvalidHostname)
		if tk.classify() != classSuccessGotServerHello {
			t.Fatal("unexpected result")
		}
	})
	t.Run("with tk.Target.Failure == ssl_unknown_authority", func(t *testing.T) {
		tk := new(TestKeys)
		tk.Target.Failure = asStringPtr(netxlite.FailureSSLUnknownAuthority)
		if tk.classify() != classInterferenceUnknownAuthority {
			t.Fatal("unexpected result")
		}
	})
	t.Run("with tk.Target.Failure == ssl_invalid_certificate", func(t *testing.T) {
		tk := new(TestKeys)
		tk.Target.Failure = asStringPtr(netxlite.FailureSSLInvalidCertificate)
		if tk.classify() != classInterferenceInvalidCertificate {
			t.Fatal("unexpected result")
		}
	})
	t.Run("with tk.Target.Failure == generic_timeout_error #1", func(t *testing.T) {
		tk := new(TestKeys)
		tk.Target.Failure = asStringPtr(netxlite.FailureGenericTimeoutError)
		if tk.classify() != classAnomalyTimeout {
			t.Fatal("unexpected result")
		}
	})
	t.Run("with tk.Target.Failure == generic_timeout_error #2", func(t *testing.T) {
		tk := new(TestKeys)
		tk.Target.Failure = asStringPtr(netxlite.FailureGenericTimeoutError)
		tk.Control.Failure = asStringPtr(netxlite.FailureGenericTimeoutError)
		if tk.classify() != classAnomalyTestHelperUnreachable {
			t.Fatal("unexpected result")
		}
	})
	t.Run("with tk.Target.Failure == unknown_failure", func(t *testing.T) {
		tk := new(TestKeys)
		tk.Target.Failure = asStringPtr("unknown_failure")
		if tk.classify() != classAnomalyUnexpectedFailure {
			t.Fatal("unexpected result")
		}
	})
}

func TestNewExperimentMeasurer(t *testing.T) {
	measurer := NewExperimentMeasurer(Config{})
	if measurer.ExperimentName() != "nsni_blocking" {
		t.Fatal("unexpected name")
	}
	if measurer.ExperimentVersion() != "0.1.0" {
		t.Fatal("unexpected version")
	}
}

func TestMeasurerMeasureNoMeasurementInput(t *testing.T) {
	measurer := NewExperimentMeasurer(Config{
		ControlSNI: "example.org",
	})
	measurement := &model.Measurement{}
	args := &model.ExperimentArgs{
		Callbacks:   model.NewPrinterCallbacks(log.Log),
		Measurement: measurement,
		Session:     newsession(),
	}
	err := measurer.Run(context.Background(), args)
	if err.Error() != "Experiment requires measurement.Input" {
		t.Fatal("not the error we expected")
	}
}

func TestMeasurerMeasureWithInvalidInput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancel the context
	measurer := NewExperimentMeasurer(Config{
		ControlSNI: "example.org",
	})
	measurement := &model.Measurement{
		Input: "\t",
	}
	args := &model.ExperimentArgs{
		Callbacks:   model.NewPrinterCallbacks(log.Log),
		Measurement: measurement,
		Session:     newsession(),
	}
	err := measurer.Run(ctx, args)
	if err == nil {
		t.Fatal("expected an error here")
	}
}

func TestMaybeURLToSNI(t *testing.T) {
	r, err := maybeURLToSNI(model.MeasurementTarget("\t"))
	if err == nil {
		t.Fatal("Expected an error here")
	}
	if r != "" {
		t.Fatalf("Unexpected non-empty SNI: %s", r)
	}
	r, err = maybeURLToSNI("google.com")
	if r != "google.com" {
		t.Fatalf("Unexpected SNI, expected: %s, got %s", "google.com", r)
	}
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
	r, err = maybeURLToSNI(model.MeasurementTarget("https://google.com"))
	if r != "google.com" {
		t.Fatalf("Unexpected SNI, expected: %s, got %s", "google.com", r)
	}
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
}
