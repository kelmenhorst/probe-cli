package telegram

//
// SystemDNS
//
// This code was generated by `boilerplate' using
// the system-resolver template.
//

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/ooni/probe-cli/v3/internal/atomicx"
	"github.com/ooni/probe-cli/v3/internal/measurexlite"
	"github.com/ooni/probe-cli/v3/internal/model"
)

// Resolves web.telegram.org using the system resolver.
//
// The zero value of this structure IS NOT valid and you MUST initialize
// all the fields marked as MANDATORY before using this structure.
type SystemDNS struct {
	// IDGenerator is the MANDATORY atomic int64 to generate task IDs.
	IDGenerator *atomicx.Int64

	// Logger is the MANDATORY logger to use.
	Logger model.Logger

	// TestKeys is MANDATORY and contains the TestKeys.
	TestKeys *TestKeys

	// ZeroTime is the MANDATORY zero time of the measurement.
	ZeroTime time.Time

	// WaitGroup is the MANDATORY wait group this task belongs to.
	WaitGroup *sync.WaitGroup
}

// Start starts this task in a background goroutine.
func (t *SystemDNS) Start(ctx context.Context) {
	t.WaitGroup.Add(1)
	index := t.IDGenerator.Add(1)
	go func() {
		defer t.WaitGroup.Done() // synchronize with the parent
		t.Run(ctx, index)
	}()
}

// Run runs this task in the current goroutine.
func (t *SystemDNS) Run(parentCtx context.Context, index int64) {
	// create context with attached a timeout
	const timeout = 4 * time.Second // TODO: consider changing
	lookupCtx, lookpCancel := context.WithTimeout(parentCtx, timeout)
	defer lookpCancel()

	// create trace
	trace := measurexlite.NewTrace(index, t.ZeroTime)

	// start the operation logger
	ol := measurexlite.NewOperationLogger(t.Logger, "SystemDNS#%d: %s", index, webTelegramOrg)

	// runs the lookup
	reso := trace.NewStdlibResolver(t.Logger)
	addrs, err := reso.LookupHost(lookupCtx, webTelegramOrg)
	_ = trace.DNSLookupsFromRoundTrip() // TODO: save
	if err != nil {
		ol.Stop(err)
		return
	}

	// emit successful log message
	ol.Stop(nil)

	// (typically) fan out a number of child async tasks to use the IP addrs
	for _, addr := range addrs {
		t.startWebHTTPTask(parentCtx, addr)
		t.startWebHTTPSTask(parentCtx, addr)
	}
}

// webTelegramOrg is the SNI and host header for telegram web.
const webTelegramOrg = "web.telegram.org"

// startWebHTTPTask starts a WebHTTPTask for this addr.
func (t *SystemDNS) startWebHTTPTask(ctx context.Context, addr string) {
	task := &WebHTTPTask{
		Address:     net.JoinHostPort(addr, "80"),
		IDGenerator: t.IDGenerator,
		Logger:      t.Logger,
		TestKeys:    t.TestKeys,
		ZeroTime:    t.ZeroTime,
		WaitGroup:   t.WaitGroup,
		HostHeader:  webTelegramOrg,
		URLPath:     "",
		URLRawQuery: "",
	}
	task.Start(ctx)
}

// startWebHTTPSTask starts a WebHTTPSTask for this addr.
func (t *SystemDNS) startWebHTTPSTask(ctx context.Context, addr string) {
	task := &WebHTTPSTask{
		Address:     net.JoinHostPort(addr, "443"),
		IDGenerator: t.IDGenerator,
		Logger:      t.Logger,
		TestKeys:    t.TestKeys,
		ZeroTime:    t.ZeroTime,
		WaitGroup:   t.WaitGroup,
		ALPN:        []string{}, // default is okay
		SNI:         webTelegramOrg,
		HostHeader:  webTelegramOrg,
		URLPath:     "",
		URLRawQuery: "",
	}
	task.Start(ctx)
}
