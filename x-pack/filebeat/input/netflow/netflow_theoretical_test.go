package netflow

import (
	"fmt"
	v2 "github.com/elastic/beats/v7/filebeat/input/v2"
	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common/atomic"
	"github.com/elastic/beats/v7/libbeat/management/status"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	"net"
	"sync"
	"testing"
	"time"
)

// MockBeatClient mocks the Client interface
type mockBeatClient struct {
	eventsCounter     atomic.Uint64
	closed            bool
	mtx               sync.Mutex
	lastSendTime      time.Time
	lastPrintedEvents uint64
}

// GetEvents returns the published events
func (c *mockBeatClient) GetEventsCount() uint64 {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	return c.eventsCounter.Load()
}

func (c *mockBeatClient) Process(event *beat.Event) (*beat.Event, error) {
	return event, nil
}

// Publish mocks the Client Publish method
func (c *mockBeatClient) Publish(e beat.Event) {
	c.PublishAll([]beat.Event{e})
}

// PublishAll mocks the Client PublishAll method
func (c *mockBeatClient) PublishAll(events []beat.Event) {
	time.Sleep(4 * time.Millisecond)
	//
	//c.mtx.Lock()
	//defer c.mtx.Unlock()

	c.eventsCounter.Add(uint64(len(events)))
}

// Close mocks the Client Close method
func (c *mockBeatClient) Close() error {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.closed {
		return fmt.Errorf("mock client already closed")
	}

	c.closed = true
	return nil
}

// mockPipeline mocks the PipelineConnector interface
type mockPipeline struct {
	clients []*mockBeatClient
	mtx     sync.Mutex
}

// GetAllEvents returns all events associated with a pipeline
func (pc *mockPipeline) GetAllEventCounter() uint64 {
	counter := uint64(0)
	for _, clientEvents := range pc.clients {
		counter += clientEvents.GetEventsCount()
	}

	return counter
}

// Connect mocks the PipelineConnector Connect method
func (pc *mockPipeline) Connect() (beat.Client, error) {
	return pc.ConnectWith(beat.ClientConfig{})
}

// ConnectWith mocks the PipelineConnector ConnectWith method
func (pc *mockPipeline) ConnectWith(beat.ClientConfig) (beat.Client, error) {
	pc.mtx.Lock()
	defer pc.mtx.Unlock()

	c := &mockBeatClient{}

	pc.clients = append(pc.clients, c)

	return c, nil
}

// HasConnectedClients returns true if there are clients connected.
func (pc *mockPipeline) HasConnectedClients() bool {
	pc.mtx.Lock()
	defer pc.mtx.Unlock()

	return len(pc.clients) > 0
}

type mockStatusReporter struct {
	status chan status.Status
}

func (m *mockStatusReporter) UpdateStatus(status status.Status, msg string) {
	select {
	case m.status <- status:
	default:
		// ignore
	}
}

func TestNetFlowPerf(t *testing.T) {
	pluginCfg, err := conf.NewConfigFrom(mapstr.M{
		"id":                    "netflow_integration_test",
		"host":                  "localhost:6006",
		"expiration_timeout":    "30m",
		"queue_size":            2 * 10 * 1600,
		"detect_sequence_reset": true,
		"max_message_size":      "10KiB",
		"number_of_workers":     350,
	})
	require.NoError(t, err)

	netflowPlugin, err := Plugin(logp.NewLogger("netflow_test")).Manager.Create(pluginCfg)
	require.NoError(t, err)

	input, ok := netflowPlugin.(*netflowInput)
	require.True(t, ok)

	mockPipeline := &mockPipeline{}

	ctx, cancelFn := newV2Context("temp")
	statusChan := make(chan status.Status)
	ctx.StatusReporter = &mockStatusReporter{
		status: statusChan,
	}
	errChan := make(chan error)
	go func() {
		defer close(errChan)
		errChan <- netflowPlugin.Run(ctx, mockPipeline)
	}()

	running := true
	for running {
		select {
		case err := <-errChan:
			t.Fatalf("netflow plugin exited with error: %v", err)
		case sts := <-statusChan:
			running = sts == status.Running
		case <-time.After(600 * time.Second):
			t.Fatalf("timed out waiting for beat to become healthy")
		}
	}

	goCtx := v2.GoContextFromCanceler(ctx.Cancelation)

	defer cancelFn()

	require.Eventually(t, mockPipeline.HasConnectedClients, 5*time.Second, 100*time.Millisecond,
		"no client has connected to the pipeline")

	require.Eventually(t, func() bool {
		return input.started
	}, 5*time.Second, 100*time.Millisecond, "netflow input didn't start")

	udpAddr, err := net.ResolveUDPAddr("udp", ":6006")
	require.NoError(t, err)

	conn, err := net.DialUDP("udp", nil, udpAddr)
	require.NoError(t, err)

	f, err := pcap.OpenOffline("testdata/performance/perf.pcap")
	require.NoError(t, err)
	defer f.Close()

	var totalBytes, totalPackets int

	doneWriting := false
	go func() {
		timer := time.NewTicker(500 * time.Millisecond)
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
				t.Log("total_flows: ", input.metrics.flows.Get(), " packets_sent: ", totalPackets, " discarded_events: ", input.metrics.discardedEvents.Get())
				if doneWriting {
					cancelFn()
					return
				}
			case <-ctx.Cancelation.Done():
				return
			}
		}
	}()

	// Process packets in PCAP and get flow records.
	rateLimit := 40000
	limiter := rate.NewLimiter(rate.Limit(rateLimit), rateLimit)
	packetSource := gopacket.NewPacketSource(f, f.LinkType())
	for pkt := range packetSource.Packets() {
		if totalPackets%rateLimit == 0 {
			err := limiter.WaitN(goCtx, rateLimit)
			require.NoError(t, err)
		}

		payloadData := pkt.TransportLayer().LayerPayload()

		n, err := conn.Write(payloadData)
		require.NoError(t, err)

		totalBytes += n
		totalPackets++
	}

	doneWriting = true
	//time.Sleep(10 * time.Minute)

	require.Zero(t, input.metrics.discardedEvents.Get())

	select {
	case <-ctx.Cancelation.Done():
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(20 * time.Second):
		t.Fatal("netflow plugin did not stop")
	}
}
