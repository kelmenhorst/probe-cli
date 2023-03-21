// Package nsniblocking contains the SNI blocking network experiment.
//
// See https://github.com/ooni/spec/blob/master/nettests/ts-024-sni-blocking.md.
package nsniblocking

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ooni/probe-cli/v3/internal/dslx"
	"github.com/ooni/probe-cli/v3/internal/model"
	"github.com/ooni/probe-cli/v3/internal/netxlite"
	"github.com/ooni/probe-cli/v3/internal/tracex"
)

const (
	testName    = "nsni_blocking"
	testVersion = "0.1.0"
)

// Config contains the experiment config.
type Config struct {
	// ControlSNI is the SNI to be used for the control.
	ControlSNI string

	// TestHelperAddress is the address of the test helper.
	TestHelperAddress string

	// ResolverURL is the URL describing the resolver to use.
	ResolverURL string
}

// Subresult contains the keys of a single measurement
// that targets either the target or the control.
type Subresult struct {
	Failure       *string                  `json:"failure"`
	NetworkEvents []tracex.NetworkEvent    `json:"network_events"`
	SNI           string                   `json:"sni"`
	TCPConnect    []tracex.TCPConnectEntry `json:"tcp_connect"`
	THAddress     string                   `json:"th_address"`
	TLSHandshakes []tracex.TLSHandshake    `json:"tls_handshakes"`
	Cached        bool                     `json:"-"`
}

// mergeObservations updates the TestKeys using the given [Observations] (goroutine safe).
func (tk *Subresult) mergeObservations(obs []*dslx.Observations) {
	for _, o := range obs {
		for _, e := range o.NetworkEvents {
			tk.NetworkEvents = append(tk.NetworkEvents, *e)
		}
		for _, e := range o.TCPConnect {
			tk.TCPConnect = append(tk.TCPConnect, *e)
		}
		for _, e := range o.TLSHandshakes {
			tk.TLSHandshakes = append(tk.TLSHandshakes, *e)
		}
	}
}

// TestKeys contains sniblocking test keys.
type TestKeys struct {
	Control Subresult              `json:"control"`
	Queries []tracex.DNSQueryEntry `json:"queries"`
	Result  string                 `json:"result"`
	Target  Subresult              `json:"target"`
}

const (
	classAnomalyTestHelperUnreachable   = "anomaly.test_helper_unreachable"
	classAnomalyTimeout                 = "anomaly.timeout"
	classAnomalyUnexpectedFailure       = "anomaly.unexpected_failure"
	classInterferenceClosed             = "interference.closed"
	classInterferenceInvalidCertificate = "interference.invalid_certificate"
	classInterferenceReset              = "interference.reset"
	classInterferenceUnknownAuthority   = "interference.unknown_authority"
	classSuccessGotServerHello          = "success.got_server_hello"
)

// classify handles the classification of the result failure
func (tk *TestKeys) classify() string {
	if tk.Target.Failure == nil {
		return classSuccessGotServerHello
	}
	switch *tk.Target.Failure {
	case netxlite.FailureConnectionRefused:
		return classAnomalyTestHelperUnreachable
	case netxlite.FailureConnectionReset:
		return classInterferenceReset
	case netxlite.FailureDNSNXDOMAINError, netxlite.FailureAndroidDNSCacheNoData:
		return classAnomalyTestHelperUnreachable
	case netxlite.FailureEOFError:
		return classInterferenceClosed
	case netxlite.FailureGenericTimeoutError:
		if tk.Control.Failure != nil {
			return classAnomalyTestHelperUnreachable
		}
		return classAnomalyTimeout
	case netxlite.FailureSSLInvalidCertificate:
		return classInterferenceInvalidCertificate
	case netxlite.FailureSSLInvalidHostname:
		return classSuccessGotServerHello
	case netxlite.FailureSSLUnknownAuthority:
		return classInterferenceUnknownAuthority
	}
	return classAnomalyUnexpectedFailure
}

// Measurer performs the measurement.
type Measurer struct {
	thAddrs *dslx.AddressSet
	cache   map[string]Subresult
	config  Config
	mu      sync.Mutex
	idGen   atomic.Int64
}

// ExperimentName implements ExperimentMeasurer.ExperiExperimentName.
func (m *Measurer) ExperimentName() string {
	return testName
}

// ExperimentVersion implements ExperimentMeasurer.ExperimentVersion.
func (m *Measurer) ExperimentVersion() string {
	return testVersion
}

func (m *Measurer) lookupTH(
	ctx context.Context,
	logger model.Logger,
	zeroTime time.Time,
	resolverURL string,
	thaddr string,
) *dslx.Maybe[*dslx.ResolvedAddresses] {
	thaddrHost, _, _ := net.SplitHostPort(thaddr) // TODO: handle error?
	// describe the DNS measurement input
	dnsInput := dslx.NewDomainToResolve(
		dslx.DomainName(thaddrHost),
		dslx.DNSLookupOptionIDGenerator(&m.idGen),
		dslx.DNSLookupOptionLogger(logger),
		dslx.DNSLookupOptionZeroTime(zeroTime),
	)
	// construct resolver
	lookup := dslx.DNSLookupGetaddrinfo()
	if resolverURL != "" {
		lookup = dslx.DNSLookupUDP(resolverURL)
	}
	// run the DNS Lookup
	return lookup.Apply(ctx, dnsInput)
}

// measureone measures a single test SNI with the given thaddr.
func (m *Measurer) measureone(
	ctx context.Context,
	sess model.ExperimentSession,
	zeroTime time.Time,
	sni string,
	thaddr string,
) Subresult {
	// slightly delay the measurement
	gen := rand.New(rand.NewSource(time.Now().UnixNano()))
	sleeptime := time.Duration(gen.Intn(250)) * time.Millisecond
	select {
	case <-time.After(sleeptime):
	case <-ctx.Done():
		s := netxlite.FailureInterrupted
		return Subresult{
			Failure:   &s,
			THAddress: thaddr,
			SNI:       sni,
		}
	}

	// create the set of endpoints
	endpoints := m.thAddrs.ToEndpoints(
		dslx.EndpointNetwork("tcp"),
		dslx.EndpointPort(443),
		dslx.EndpointOptionDomain(thaddr),
		dslx.EndpointOptionIDGenerator(&m.idGen),
		dslx.EndpointOptionLogger(sess.Logger()),
		dslx.EndpointOptionZeroTime(zeroTime),
	)

	// create the established connections pool
	connpool := &dslx.ConnPool{}
	defer connpool.Close()

	// count the number of successes
	successes := dslx.Counter[*dslx.TLSConnection]{}

	// run tls handshake measurement
	httpsResults := dslx.Map(
		ctx,
		dslx.Parallelism(2),
		dslx.Compose3(
			dslx.TCPConnect(connpool),
			dslx.TLSHandshake(
				connpool,
				dslx.TLSHandshakeOptionServerName(sni),
			),
			successes.Func(), // number of times we arrive here
		),
		dslx.StreamList(endpoints...),
	)
	coll := dslx.Collect(httpsResults)

	// create a subresult
	subresult := Subresult{
		SNI:       sni,
		THAddress: thaddr,
	}
	// extract and merge observations
	subresult.mergeObservations(dslx.ExtractObservations(coll...))

	// extract first error
	_, firstError := dslx.FirstErrorExcludingBrokenIPv6Errors(coll...)
	if firstError != nil {
		subresult.Failure = tracex.NewFailure(firstError)
	}
	return subresult
}

// measureonewithcache measures thaddr with the given sni.
// If thaddr has been measured with the same sni before, the cached subresult is returned.
func (m *Measurer) measureonewithcache(
	ctx context.Context,
	output chan<- Subresult,
	sess model.ExperimentSession,
	zeroTime time.Time,
	sni string,
	thaddr string,
) {
	cachekey := sni + thaddr
	m.mu.Lock()
	smk, okay := m.cache[cachekey]
	m.mu.Unlock()
	if okay {
		output <- smk
		return
	}
	smk = m.measureone(ctx, sess, zeroTime, sni, thaddr)
	output <- smk
	smk.Cached = true
	m.mu.Lock()
	m.cache[cachekey] = smk
	m.mu.Unlock()
}

func (m *Measurer) startall(
	ctx context.Context,
	sess model.ExperimentSession,
	zeroTime time.Time,
	inputs []string,
) <-chan Subresult {
	outputs := make(chan Subresult, len(inputs))
	for _, input := range inputs {
		go m.measureonewithcache(ctx, outputs, sess, zeroTime, input, m.config.TestHelperAddress)
	}
	return outputs
}

func processall(
	outputs <-chan Subresult,
	measurement *model.Measurement,
	inputs []string,
	sess model.ExperimentSession,
	controlSNI string,
	tk *TestKeys,
) {
	var (
		current int
	)
	for smk := range outputs {
		if smk.SNI == controlSNI {
			tk.Control = smk
		} else if smk.SNI == string(measurement.Input) {
			tk.Target = smk
		} else {
			panic("unexpected smk.SNI")
		}
		current++
		sess.Logger().Debugf(
			"sni_blocking: %s: %s [cached: %+v]", smk.SNI,
			asString(smk.Failure), smk.Cached)
		if current >= len(inputs) {
			break
		}
	}
	tk.Result = tk.classify()
	sess.Logger().Infof("sni_blocking: result: %s", tk.Result)
}

// maybeURLToSNI handles the case where the input is from the test-lists
// and hence every input is a URL rather than a domain.
func maybeURLToSNI(input model.MeasurementTarget) (model.MeasurementTarget, error) {
	parsed, err := url.Parse(string(input))
	if err != nil {
		return "", err
	}
	if parsed.Path == string(input) {
		return input, nil
	}
	return model.MeasurementTarget(parsed.Hostname()), nil
}

// Run implements ExperimentMeasurer.Run.
func (m *Measurer) Run(ctx context.Context, args *model.ExperimentArgs) error {
	m.idGen = atomic.Int64{}
	measurement := args.Measurement
	tk := new(TestKeys)
	measurement.TestKeys = tk
	sess := args.Session
	m.mu.Lock()
	if m.cache == nil {
		m.cache = make(map[string]Subresult)
	}
	m.mu.Unlock()

	if m.config.ControlSNI == "" {
		m.config.ControlSNI = "example.org"
	}
	if measurement.Input == "" {
		return errors.New("Experiment requires measurement.Input")
	}
	maybeParsed, err := maybeURLToSNI(measurement.Input)
	if err != nil {
		return err
	}
	if m.config.TestHelperAddress == "" {
		m.config.TestHelperAddress = net.JoinHostPort(
			m.config.ControlSNI, "443",
		)
	}

	// Lookup testhelper address.
	//
	// TODO(bassosimone, kelmenhorst): allow the user to configure DoT or DoH,
	// make sure that the classify logic is robust to that.
	//
	// See https://github.com/ooni/probe-engine/issues/392.
	dnsResult := m.lookupTH(
		ctx,
		sess.Logger(),
		measurement.MeasurementStartTimeSaved,
		m.config.ResolverURL,
		m.config.TestHelperAddress,
	)
	for _, o := range dnsResult.Observations {
		for _, e := range o.Queries {
			tk.Queries = append(tk.Queries, *e)
		}
	}
	// if the lookup of the testhelper address has failed, we cannot continue
	if dnsResult.Error != nil {
		tk.Result = classAnomalyTestHelperUnreachable
		return nil
	}
	// obtain a unique set of IP addresses w/o bogons inside it
	m.thAddrs = dslx.NewAddressSet(dnsResult).RemoveBogons()

	measurement.Input = maybeParsed
	inputs := []string{m.config.ControlSNI}
	if string(measurement.Input) != m.config.ControlSNI {
		inputs = append(inputs, string(measurement.Input))
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second*time.Duration(len(inputs)))
	defer cancel()

	outputs := m.startall(ctx, sess, measurement.MeasurementStartTimeSaved, inputs)
	processall(outputs, measurement, inputs, sess, m.config.ControlSNI, tk)
	return nil
}

// NewExperimentMeasurer creates a new ExperimentMeasurer.
func NewExperimentMeasurer(config Config) model.ExperimentMeasurer {
	return &Measurer{config: config}
}

func asString(failure *string) (result string) {
	result = "success"
	if failure != nil {
		result = *failure
	}
	return
}

// SummaryKeys contains summary keys for this experiment.
//
// Note that this structure is part of the ABI contract with ooniprobe
// therefore we should be careful when changing it.
type SummaryKeys struct {
	IsAnomaly bool `json:"-"`
}

// GetSummaryKeys implements model.ExperimentMeasurer.GetSummaryKeys.
func (m *Measurer) GetSummaryKeys(measurement *model.Measurement) (interface{}, error) {
	return SummaryKeys{IsAnomaly: false}, nil
}
