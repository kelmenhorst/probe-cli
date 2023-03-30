// Package nfbmessenger contains the Facebook Messenger network experiment.
//
// See https://github.com/ooni/spec/blob/master/nettests/ts-019-facebook-messenger.md
package nfbmessenger

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ooni/probe-cli/v3/internal/dslx"
	"github.com/ooni/probe-cli/v3/internal/model"
	"github.com/ooni/probe-cli/v3/internal/tracex"
)

const (
	// FacebookASN is Facebook's ASN
	FacebookASN = 32934

	// ServiceSTUN is the STUN service
	ServiceSTUN = "stun.fbsbx.com"

	// ServiceBAPI is the b-api service
	ServiceBAPI = "b-api.facebook.com"

	// ServiceBGraph is the b-graph service
	ServiceBGraph = "b-graph.facebook.com"

	// ServiceEdge is the edge service
	ServiceEdge = "edge-mqtt.facebook.com"

	// ServiceExternalCDN is the external CDN service
	ServiceExternalCDN = "external.xx.fbcdn.net"

	// ServiceScontentCDN is the scontent CDN service
	ServiceScontentCDN = "scontent.xx.fbcdn.net"

	// ServiceStar is the star service
	ServiceStar = "star.c10r.facebook.com"

	testName    = "nfacebook_messenger"
	testVersion = "0.1.0"
)

// Config contains the experiment config.
type Config struct{}

// TestKeys contains the experiment results
type TestKeys struct {
	mu sync.Mutex

	Agent         string                   `json:"agent"`                // df-001-httpt
	SOCKSProxy    string                   `json:"socksproxy,omitempty"` // df-001-httpt
	Queries       []tracex.DNSQueryEntry   `json:"queries"`              // df-002-dnst
	TCPConnect    []tracex.TCPConnectEntry `json:"tcp_connect"`          // df-005-tcpconnect
	NetworkEvents []tracex.NetworkEvent    `json:"network_events"`       // df-008-netevents

	FacebookBAPIDNSConsistent        *bool `json:"facebook_b_api_dns_consistent"`
	FacebookBAPIReachable            *bool `json:"facebook_b_api_reachable"`
	FacebookBGraphDNSConsistent      *bool `json:"facebook_b_graph_dns_consistent"`
	FacebookBGraphReachable          *bool `json:"facebook_b_graph_reachable"`
	FacebookEdgeDNSConsistent        *bool `json:"facebook_edge_dns_consistent"`
	FacebookEdgeReachable            *bool `json:"facebook_edge_reachable"`
	FacebookExternalCDNDNSConsistent *bool `json:"facebook_external_cdn_dns_consistent"`
	FacebookExternalCDNReachable     *bool `json:"facebook_external_cdn_reachable"`
	FacebookScontentCDNDNSConsistent *bool `json:"facebook_scontent_cdn_dns_consistent"`
	FacebookScontentCDNReachable     *bool `json:"facebook_scontent_cdn_reachable"`
	FacebookStarDNSConsistent        *bool `json:"facebook_star_dns_consistent"`
	FacebookStarReachable            *bool `json:"facebook_star_reachable"`
	FacebookSTUNDNSConsistent        *bool `json:"facebook_stun_dns_consistent"`
	FacebookSTUNReachable            *bool `json:"facebook_stun_reachable"`
	FacebookDNSBlocking              *bool `json:"facebook_dns_blocking"`
	FacebookTCPBlocking              *bool `json:"facebook_tcp_blocking"`
}

// mergeObservations updates the TestKeys using the given [Observations] (goroutine safe).
func (tk *TestKeys) mergeObservations(obs []*dslx.Observations) {
	defer tk.mu.Unlock()
	tk.mu.Lock()

	for _, o := range obs {
		for _, e := range o.NetworkEvents {
			tk.NetworkEvents = append(tk.NetworkEvents, *e)
		}
		for _, e := range o.Queries {
			tk.Queries = append(tk.Queries, *e)
		}
		for _, e := range o.TCPConnect {
			tk.TCPConnect = append(tk.TCPConnect, *e)
		}
	}
}

func (tk *TestKeys) getDNSStatusKey(service string) **bool {
	switch service {
	case ServiceSTUN:
		return &tk.FacebookSTUNDNSConsistent
	case ServiceBAPI:
		return &tk.FacebookBAPIDNSConsistent
	case ServiceBGraph:
		return &tk.FacebookBGraphDNSConsistent
	case ServiceEdge:
		return &tk.FacebookEdgeDNSConsistent
	case ServiceExternalCDN:
		return &tk.FacebookExternalCDNDNSConsistent
	case ServiceScontentCDN:
		return &tk.FacebookScontentCDNDNSConsistent
	case ServiceStar:
		return &tk.FacebookStarDNSConsistent
	default:
		return nil // should not happen
	}
}

func (tk *TestKeys) getEndpointStatusKey(service string) **bool {
	switch service {
	case ServiceBAPI:
		return &tk.FacebookBAPIReachable
	case ServiceBGraph:
		return &tk.FacebookBGraphReachable
	case ServiceEdge:
		return &tk.FacebookEdgeReachable
	case ServiceExternalCDN:
		return &tk.FacebookExternalCDNReachable
	case ServiceScontentCDN:
		return &tk.FacebookScontentCDNReachable
	case ServiceStar:
		return &tk.FacebookStarReachable
	default:
		return nil // should not happen
	}
}

var (
	trueValue  = true
	falseValue = false
)

// computeDNSStatus computes the DNS status of a specific endpoint.
func (tk *TestKeys) computeDNSStatus(dnsStatus **bool, r *dslx.Maybe[*dslx.ResolvedAddresses]) {
	if r.Error != nil {
		defer tk.mu.Unlock()
		tk.mu.Lock()
		tk.FacebookDNSBlocking = &trueValue
		*dnsStatus = &falseValue
		return
	}
	for _, o := range r.Observations {
		for _, query := range (*o).Queries {
			for _, ans := range query.Answers {
				if ans.ASN != FacebookASN && ans.AnswerType != "CNAME" {
					defer tk.mu.Unlock()
					tk.mu.Lock()
					tk.FacebookDNSBlocking = &trueValue
					*dnsStatus = &falseValue
					return // DNS is lying
				}
			}
		}
	}
	// all good
	*dnsStatus = &trueValue
}

// setEndpointError sets the TCP status of a failed endpoint.
func (tk *TestKeys) setEndpointError(endpointStatus **bool) {
	defer tk.mu.Unlock()
	tk.mu.Lock()
	*endpointStatus = &falseValue
	tk.FacebookTCPBlocking = &trueValue
	return
}

// Measurer performs the measurement
type Measurer struct {
	// Config contains the experiment settings. If empty we
	// will be using default settings.
	Config Config

	idGen atomic.Int64
}

// ExperimentName implements ExperimentMeasurer.ExperimentName
func (m Measurer) ExperimentName() string {
	return testName
}

// ExperimentVersion implements ExperimentMeasurer.ExperimentVersion
func (m Measurer) ExperimentVersion() string {
	return testVersion
}

func (m Measurer) measureTarget(
	ctx context.Context,
	sess model.ExperimentSession,
	zeroTime time.Time,
	tk *TestKeys,
	domain string,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	// DNS measurement input
	dnsInput := dslx.NewDomainToResolve(
		dslx.DomainName(domain),
		dslx.DNSLookupOptionIDGenerator(&m.idGen),
		dslx.DNSLookupOptionLogger(sess.Logger()),
		dslx.DNSLookupOptionZeroTime(zeroTime),
	)
	// construct getaddrinfo resolver
	lookup := dslx.DNSLookupGetaddrinfo()

	// run the DNS Lookup
	dnsResult := lookup.Apply(ctx, dnsInput)

	// extract and merge observations with the test keys
	tk.mergeObservations(dslx.ExtractObservations(dnsResult))

	tk.computeDNSStatus(tk.getDNSStatusKey(domain), dnsResult)

	// "We ignore the IPs resolved to by the stun endpoint since that is UDP based service."
	// https://github.com/ooni/spec/blob/master/nettests/ts-019-facebook-messenger.md
	if domain == ServiceSTUN {
		return
	}

	// obtain a unique set of IP addresses w/o bogons inside it
	ipAddrs := dslx.NewAddressSet(dnsResult).RemoveBogons()

	// create the set of endpoints
	endpoints := ipAddrs.ToEndpoints(
		dslx.EndpointNetwork("tcp"),
		dslx.EndpointPort(443),
		dslx.EndpointOptionDomain(domain),
		dslx.EndpointOptionIDGenerator(&m.idGen),
		dslx.EndpointOptionLogger(sess.Logger()),
		dslx.EndpointOptionZeroTime(zeroTime),
	)

	// count the number of successful TCP Connects per domain
	successes := dslx.Counter[*dslx.TCPConnection]{}

	// create the established connections pool
	connpool := &dslx.ConnPool{}
	defer connpool.Close()

	// create function for the 443/tcp measurement
	tcpFunction := dslx.Compose2(
		dslx.TCPConnect(connpool),
		successes.Func(), // count number of times we arrive here
	)

	// run 443/tcp measurement
	tcpResults := dslx.Map(
		ctx,
		dslx.Parallelism(2),
		tcpFunction,
		dslx.StreamList(endpoints...),
	)
	coll := dslx.Collect(tcpResults)

	// extract and merge observations with the test keys
	tk.mergeObservations(dslx.ExtractObservations(coll...))

	// if we saw no successes, then this domain is blocked
	s := tk.getEndpointStatusKey(domain)
	if successes.Value() <= 0 {
		tk.setEndpointError(s) // set the error
		return
	}
	// all good
	*s = &trueValue
}

// Run implements ExperimentMeasurer.Run
func (m Measurer) Run(ctx context.Context, args *model.ExperimentArgs) error {
	measurement := args.Measurement
	tk := new(TestKeys)
	measurement.TestKeys = tk
	tk.Agent = "redirect"
	m.idGen = atomic.Int64{}

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// generate targets
	services := []string{
		ServiceSTUN, ServiceBAPI, ServiceBGraph, ServiceEdge, ServiceExternalCDN,
		ServiceScontentCDN, ServiceStar,
	}

	// run measurements in parallel
	wg := sync.WaitGroup{}
	for _, service := range services {
		wg.Add(1)
		go m.measureTarget(ctx, args.Session, measurement.MeasurementStartTimeSaved, tk, service, &wg)
	}

	wg.Wait()

	// if we haven't yet determined the status of DNS blocking and TCP blocking
	// then no blocking has been detected and we can set them
	if tk.FacebookDNSBlocking == nil {
		tk.FacebookDNSBlocking = &falseValue
	}
	if tk.FacebookTCPBlocking == nil {
		tk.FacebookTCPBlocking = &falseValue
	}
	return nil
}

// NewExperimentMeasurer creates a new ExperimentMeasurer.
func NewExperimentMeasurer(config Config) model.ExperimentMeasurer {
	return Measurer{Config: config}
}

// SummaryKeys contains summary keys for this experiment.
//
// Note that this structure is part of the ABI contract with ooniprobe
// therefore we should be careful when changing it.
type SummaryKeys struct {
	DNSBlocking bool `json:"facebook_dns_blocking"`
	TCPBlocking bool `json:"facebook_tcp_blocking"`
	IsAnomaly   bool `json:"-"`
}

// GetSummaryKeys implements model.ExperimentMeasurer.GetSummaryKeys.
func (m Measurer) GetSummaryKeys(measurement *model.Measurement) (interface{}, error) {
	sk := SummaryKeys{IsAnomaly: false}
	tk, ok := measurement.TestKeys.(*TestKeys)
	if !ok {
		return sk, errors.New("invalid test keys type")
	}
	dnsBlocking := tk.FacebookDNSBlocking != nil && *tk.FacebookDNSBlocking
	tcpBlocking := tk.FacebookTCPBlocking != nil && *tk.FacebookTCPBlocking
	sk.DNSBlocking = dnsBlocking
	sk.TCPBlocking = tcpBlocking
	sk.IsAnomaly = dnsBlocking || tcpBlocking
	return sk, nil
}
