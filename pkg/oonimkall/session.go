package oonimkall

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"runtime"
	"sync"

	"github.com/ooni/probe-cli/v3/internal/atomicx"
	"github.com/ooni/probe-cli/v3/internal/engine"
	"github.com/ooni/probe-cli/v3/internal/engine/legacy/assetsdir"
	"github.com/ooni/probe-cli/v3/internal/engine/model"
	"github.com/ooni/probe-cli/v3/internal/engine/probeservices"
	"github.com/ooni/probe-cli/v3/internal/kvstore"
	"github.com/ooni/probe-cli/v3/internal/runtimex"
)

// AtomicInt64 allows us to export atomicx.Int64 variables to
// mobile libraries so we can use them in testing.
type AtomicInt64 struct {
	*atomicx.Int64
}

// These two variables contain metrics pertaining to the number
// of Sessions and Contexts that are currently being used.
var (
	ActiveSessions = &AtomicInt64{&atomicx.Int64{}}
	ActiveContexts = &AtomicInt64{&atomicx.Int64{}}
)

// Logger is the logger used by a Session. You should implement a class
// compatible with this interface in Java/ObjC and then save a reference
// to this instance in the SessionConfig object. All log messages that
// the Session will generate will be routed to this Logger.
type Logger interface {
	// Debug handles debug messages.
	Debug(msg string)

	// Info handles informational messages.
	Info(msg string)

	// Warn handles warning messages.
	Warn(msg string)
}

// ExperimentCallbacks contains experiment callbacks.
type ExperimentCallbacks interface {
	// OnProgress provides information about an experiment progress.
	OnProgress(percentage float64, message string)
}

// SessionConfig contains configuration for a Session. You should
// fill all the mandatory fields and could also optionally fill some of
// the optional fields. Then pass this struct to NewSession.
type SessionConfig struct {
	// AssetsDir is the mandatory directory where to store assets
	// required by a Session, e.g. MaxMind DB files.
	//
	// This field is currently deprecated and unused. We will
	// remove it when we'll bump the major number.
	AssetsDir string

	// Logger is the optional logger that will receive all the
	// log messages generated by a Session. If this field is nil
	// then the session will not emit any log message.
	Logger Logger

	// Proxy allows you to optionally force a specific proxy
	// rather than using no proxy (the default).
	//
	// Use `psiphon:///` to force using Psiphon with the
	// embedded configuration file. Not all builds have
	// an embedded configuration file, but OONI builds have
	// such a file, so they can use this functionality.
	//
	// Use `socks5://10.0.0.1:9050/` to connect to a SOCKS5
	// proxy running on 10.0.0.1:9050. This could be, for
	// example, a suitably configured `tor` instance.
	Proxy string

	// ProbeServicesURL allows you to optionally force the
	// usage of an alternative probe service instance. This setting
	// should only be used for implementing integration tests.
	ProbeServicesURL string

	// SoftwareName is the mandatory name of the application
	// that will be using the new Session.
	SoftwareName string

	// SoftwareVersion is the mandatory version of the application
	// that will be using the new Session.
	SoftwareVersion string

	// StateDir is the mandatory directory where to store state
	// information required by a Session.
	StateDir string

	// TempDir is the mandatory directory where the Session shall
	// store temporary files. Among other tasks, Session.Close will
	// remove any temporary file created within this Session.
	TempDir string

	// TunnelDir is the directory where the Session shall store
	// persistent data regarding circumvention tunnels. This directory
	// is mandatory if you want to use tunnels.
	TunnelDir string

	// Verbose is optional. If there is a non-null Logger and this
	// field is true, then the Logger will also receive Debug messages,
	// otherwise it will not receive such messages.
	Verbose bool
}

// Session contains shared state for running experiments and/or other
// OONI related task (e.g. geolocation). Note that the Session isn't
// mean to be a long living object. The workflow is to create a Session,
// do the operations you need to do with it now, then make sure it is
// not referenced by other variables, so the Go GC can finalize it. This
// is what you would normally done with Java/ObjC.
type Session struct {
	// Hooks for testing (should not appear in Java/ObjC, because they
	// cannot be automatically transformed to Java/ObjC code.)
	TestingCheckInBeforeNewProbeServicesClient func(ctx *Context)
	TestingCheckInBeforeCheckIn                func(ctx *Context)

	cl        []context.CancelFunc
	mtx       sync.Mutex
	submitter *probeservices.Submitter
	sessp     *engine.Session
}

// NewSession is like NewSessionWithContext but without context. This
// factory is deprecated and will be removed when we bump the major
// version number of ooni/probe-cli.
func NewSession(config *SessionConfig) (*Session, error) {
	return newSessionWithContext(context.Background(), config)
}

// NewSessionWithContext creates a new session. You should use a session for running
// a set of operations in a relatively short time frame. You SHOULD NOT create
// a single session and keep it all alive for the whole app lifecyle, since
// the Session code is not specifically designed for this use case.
func NewSessionWithContext(ctx *Context, config *SessionConfig) (*Session, error) {
	return newSessionWithContext(ctx.ctx, config)
}

// newSessionWithContext implements NewSessionWithContext.
func newSessionWithContext(ctx context.Context, config *SessionConfig) (*Session, error) {
	kvstore, err := kvstore.NewFS(config.StateDir)
	if err != nil {
		return nil, err
	}

	// We cleanup the assets files used by versions of ooniprobe
	// older than v3.9.0, where we started embedding the assets
	// into the binary and use that directly. This cleanup doesn't
	// remove the whole directory but only known files inside it
	// and then the directory itself, if empty. We explicitly discard
	// the return value as it does not matter to us here.
	_, _ = assetsdir.Cleanup(config.AssetsDir)

	var availableps []model.Service
	if config.ProbeServicesURL != "" {
		availableps = append(availableps, model.Service{
			Address: config.ProbeServicesURL,
			Type:    "https",
		})
	}

	// TODO(bassosimone): write tests for this functionality.
	// See https://github.com/ooni/probe/issues/1465.
	var proxyURL *url.URL
	if config.Proxy != "" {
		var err error
		proxyURL, err = url.Parse(config.Proxy)
		if err != nil {
			return nil, err
		}
	}

	engineConfig := engine.SessionConfig{
		AvailableProbeServices: availableps,
		KVStore:                kvstore,
		Logger:                 newLogger(config.Logger, config.Verbose),
		ProxyURL:               proxyURL,
		SoftwareName:           config.SoftwareName,
		SoftwareVersion:        config.SoftwareVersion,
		TempDir:                config.TempDir,
		TunnelDir:              config.TunnelDir,
	}
	sessp, err := engine.NewSession(ctx, engineConfig)
	if err != nil {
		return nil, err
	}
	sess := &Session{sessp: sessp}
	// We use finalizers to reduce the burden of managing the
	// session from languages with a garbage collector.
	runtime.SetFinalizer(sess, sessionFinalizer)
	ActiveSessions.Add(1)
	return sess, nil
}

// sessionFinalizer finalizes a Session. While in general in Go code using a
// finalizer is probably unclean, it seems that using a finalizer when binding
// with Java/ObjC code is actually useful to simplify the apps.
func sessionFinalizer(sess *Session) {
	for _, fn := range sess.cl {
		fn()
	}
	sess.sessp.Close() // ignore return value
	ActiveSessions.Add(-1)
}

// Context is the context of an operation. You use this context
// to cancel a long running operation by calling Cancel(). Because
// you create a Context from a Session and because the Session is
// keeping track of the Context instances it owns, you do don't
// need to call the Cancel method when you're done.
type Context struct {
	cancel context.CancelFunc
	ctx    context.Context
}

// Cancel cancels pending operations using this context. This method
// is idempotent. Calling it more than once is fine. The first invocation
// cancels the context. Subsequent invocations are no-operations.
func (ctx *Context) Cancel() {
	ctx.cancel()
}

// NewContext creates an new interruptible Context.
func (sess *Session) NewContext() *Context {
	return sess.NewContextWithTimeout(-1)
}

// NewContextWithTimeout creates an new interruptible Context that will automatically
// cancel itself after the given timeout. Setting a zero or negative timeout implies
// there is no actual timeout configured for the Context, making this invocation
// equivalent to calling NewContext().
func (sess *Session) NewContextWithTimeout(timeout int64) *Context {
	sess.mtx.Lock()
	defer sess.mtx.Unlock()
	ctx, origcancel := newContext(timeout)
	ActiveContexts.Add(1)
	var once sync.Once
	cancel := func() {
		once.Do(func() {
			ActiveContexts.Add(-1)
			origcancel()
		})
	}
	sess.cl = append(sess.cl, cancel)
	return &Context{cancel: cancel, ctx: ctx}
}

// GeolocateResults contains the results of session.Geolocate.
type GeolocateResults struct {
	// ASN is the autonomous system number.
	ASN string

	// Country is the country code.
	Country string

	// IP is the IP address.
	IP string

	// Org is the commercial name of the ASN.
	Org string
}

// MaybeUpdateResources is a legacy stub. It does nothing. We will
// remove it when we're ready to bump the major number.
func (sess *Session) MaybeUpdateResources(ctx *Context) error {
	return nil
}

// Geolocate performs a geolocate operation and returns the results.
//
// This function locks the session until it's done. That is, no other operation
// can be performed as long as this function is pending.
func (sess *Session) Geolocate(ctx *Context) (*GeolocateResults, error) {
	sess.mtx.Lock()
	defer sess.mtx.Unlock()
	info, err := sess.sessp.LookupLocationContext(ctx.ctx)
	if err != nil {
		return nil, err
	}
	return &GeolocateResults{
		ASN:     info.ASNString(),
		Country: info.CountryCode,
		IP:      info.ProbeIP,
		Org:     info.NetworkName,
	}, nil
}

// SubmitMeasurementResults contains the results of a single measurement submission
// to the OONI backends using the OONI collector API.
type SubmitMeasurementResults struct {
	// UpdateMeasurement is the measurement with updated report ID.
	UpdatedMeasurement string

	// UpdatedReportID is the report ID used for the measurement.
	UpdatedReportID string
}

// Submit submits the given measurement and returns the results.
//
// This function locks the session until it's done. That is, no other operation
// can be performed as long as this function is pending.
func (sess *Session) Submit(ctx *Context, measurement string) (*SubmitMeasurementResults, error) {
	sess.mtx.Lock()
	defer sess.mtx.Unlock()
	if sess.submitter == nil {
		psc, err := sess.sessp.NewProbeServicesClient(ctx.ctx)
		if err != nil {
			return nil, err
		}
		sess.submitter = probeservices.NewSubmitter(psc, sess.sessp.Logger())
	}
	var mm model.Measurement
	if err := json.Unmarshal([]byte(measurement), &mm); err != nil {
		return nil, err
	}
	if err := sess.submitter.Submit(ctx.ctx, &mm); err != nil {
		return nil, err
	}
	data, err := json.Marshal(mm)
	runtimex.PanicOnError(err, "json.Marshal should not fail here")
	return &SubmitMeasurementResults{
		UpdatedMeasurement: string(data),
		UpdatedReportID:    mm.ReportID,
	}, nil
}

// CheckInConfigWebConnectivity contains WebConnectivity
// configuration for the check-in API.
type CheckInConfigWebConnectivity struct {
	// CategoryCodes contains zero or more category codes (e.g. "HUMR").
	CategoryCodes []string
}

// Add adds a category code to ckw.CategoryCode. This method allows you to
// edit ckw.CategoryCodes, which is inaccessible from Java/ObjC.
func (ckw *CheckInConfigWebConnectivity) Add(cat string) {
	ckw.CategoryCodes = append(ckw.CategoryCodes, cat)
}

func (ckw *CheckInConfigWebConnectivity) toModel() model.CheckInConfigWebConnectivity {
	return model.CheckInConfigWebConnectivity{
		CategoryCodes: ckw.CategoryCodes,
	}
}

// CheckInConfig contains configuration for the check-in API.
type CheckInConfig struct {
	// Charging indicates whether the phone is charging.
	Charging bool

	// OnWiFi indicates whether the phone is using the Wi-Fi.
	OnWiFi bool

	// Platform is the mobile platform (e.g. "android")
	Platform string

	// RunType indicates whether this is an automated ("timed") run
	// or otherwise a manual run initiated by the user.
	RunType string

	// SoftwareName is the name of the application.
	SoftwareName string

	// SoftwareVersion is the version of the application.
	SoftwareVersion string

	// WebConnectivity contains configuration items specific of
	// the WebConnectivity experiment.
	WebConnectivity *CheckInConfigWebConnectivity
}

// CheckInInfoWebConnectivity contains the WebConnectivity
// specific results of the check-in API call.
type CheckInInfoWebConnectivity struct {
	// ReportID is the report ID we should be using.
	ReportID string

	// URLs contains the list of URLs to measure.
	URLs []model.URLInfo
}

// URLInfo contains info on a specific URL to measure.
type URLInfo struct {
	// CategoryCode is the URL's category code (e.g. "HUMR").
	CategoryCode string

	// CountryCode is the test list from which this URL
	// comes from (e.g. "IT", "FR").
	CountryCode string

	// URL is the URL itself.
	URL string
}

// Size returns the number of URLs included into the result.
func (ckw *CheckInInfoWebConnectivity) Size() int64 {
	return int64(len(ckw.URLs))
}

// At returns the URLInfo at index idx. Note that this function will
// return nil/null if the index is out of bounds.
func (ckw *CheckInInfoWebConnectivity) At(idx int64) *URLInfo {
	if idx < 0 || int(idx) >= len(ckw.URLs) {
		return nil
	}
	w := ckw.URLs[idx]
	return &URLInfo{
		CategoryCode: w.CategoryCode,
		CountryCode:  w.CountryCode,
		URL:          w.URL,
	}
}

func newCheckInInfoWebConnectivity(ckw *model.CheckInInfoWebConnectivity) *CheckInInfoWebConnectivity {
	if ckw == nil {
		return nil
	}
	return &CheckInInfoWebConnectivity{
		ReportID: ckw.ReportID,
		URLs:     ckw.URLs,
	}
}

// CheckInInfo contains the result of the check-in API.
type CheckInInfo struct {
	// WebConnectivity contains results that are specific to
	// the WebConnectivity experiment. This field MAY be null
	// if the server's response did not contain any info.
	WebConnectivity *CheckInInfoWebConnectivity
}

// CheckIn calls the check-in API. Both ctx and config MUST NOT be nil. This
// function will fail if config is missing required settings. The return value
// is either an error or a valid CheckInInfo instance. Beware that the returned
// object MAY still contain nil fields depending on the server's response.
//
// This function locks the session until it's done. That is, no other operation
// can be performed as long as this function is pending.
func (sess *Session) CheckIn(ctx *Context, config *CheckInConfig) (*CheckInInfo, error) {
	sess.mtx.Lock()
	defer sess.mtx.Unlock()
	if config.WebConnectivity == nil {
		return nil, errors.New("oonimkall: missing webconnectivity config")
	}
	info, err := sess.sessp.LookupLocationContext(ctx.ctx)
	if err != nil {
		return nil, err
	}
	if sess.TestingCheckInBeforeNewProbeServicesClient != nil {
		sess.TestingCheckInBeforeNewProbeServicesClient(ctx) // for testing
	}
	psc, err := sess.sessp.NewProbeServicesClient(ctx.ctx)
	if err != nil {
		return nil, err
	}
	if sess.TestingCheckInBeforeCheckIn != nil {
		sess.TestingCheckInBeforeCheckIn(ctx) // for testing
	}
	cfg := model.CheckInConfig{
		Charging:        config.Charging,
		OnWiFi:          config.OnWiFi,
		Platform:        config.Platform,
		ProbeASN:        info.ASNString(),
		ProbeCC:         info.CountryCode,
		RunType:         config.RunType,
		SoftwareVersion: config.SoftwareVersion,
		WebConnectivity: config.WebConnectivity.toModel(),
	}
	result, err := psc.CheckIn(ctx.ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &CheckInInfo{
		WebConnectivity: newCheckInInfoWebConnectivity(result.WebConnectivity),
	}, nil
}

// URLListConfig contains configuration for fetching the URL list.
type URLListConfig struct {
	Categories  []string // Categories to query for (empty means all)
	CountryCode string   // CountryCode is the optional country code
	Limit       int64    // Max number of URLs (<= 0 means no limit)
}

// URLListResult contains the URLs returned from the FetchURL API
type URLListResult struct {
	Results []model.URLInfo
}

// AddCategory adds category code to the array in URLListConfig
func (ckw *URLListConfig) AddCategory(cat string) {
	ckw.Categories = append(ckw.Categories, cat)
}

// At gets the URLInfo at position idx from CheckInInfoWebConnectivity.URLs. It returns
// nil if you are using an outs of bound index.
func (ckw *URLListResult) At(idx int64) *URLInfo {
	if idx < 0 || int(idx) >= len(ckw.Results) {
		return nil
	}
	w := ckw.Results[idx]
	return &URLInfo{
		CategoryCode: w.CategoryCode,
		CountryCode:  w.CountryCode,
		URL:          w.URL,
	}
}

// Size returns the number of URLs.
func (ckw *URLListResult) Size() int64 {
	return int64(len(ckw.Results))
}

// FetchURLList fetches the list of URLs to test
func (sess *Session) FetchURLList(ctx *Context, config *URLListConfig) (*URLListResult, error) {
	sess.mtx.Lock()
	defer sess.mtx.Unlock()
	psc, err := sess.sessp.NewProbeServicesClient(ctx.ctx)
	if err != nil {
		return nil, err
	}
	if config.CountryCode == "" {
		config.CountryCode = "XX"
		info, err := sess.sessp.LookupLocationContext(ctx.ctx)
		// TODO(bassosimone): this piece of code feels wrong to me. We don't
		// want to continue if we cannot discover the country.
		if err == nil && info != nil {
			config.CountryCode = info.CountryCode
		}
	}
	cfg := model.URLListConfig{
		Categories:  config.Categories,
		CountryCode: config.CountryCode,
		Limit:       config.Limit,
	}
	result, err := psc.FetchURLList(ctx.ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &URLListResult{
		Results: result,
	}, nil
}
