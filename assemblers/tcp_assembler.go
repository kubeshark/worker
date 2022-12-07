package assemblers

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"

	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/gopacket/reassembly"
	"github.com/kubeshark/worker/diagnose"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/source"
	"github.com/rs/zerolog/log"
)

const (
	lastClosedConnectionsMaxItems = 1000
	packetsSeenLogThreshold       = 1000
	lastAckThreshold              = time.Duration(3) * time.Second
)

type connectionId string

func NewConnectionId(c string) connectionId {
	return connectionId(c)
}

type AssemblerStats struct {
	FlushedConnections int
	ClosedConnections  int
}

type TcpAssembler struct {
	*reassembly.Assembler
	streamPool             *reassembly.StreamPool
	streamFactory          *tcpStreamFactory
	ignoredPorts           []uint16
	lock                   sync.RWMutex
	lastClosedConnections  *lru.Cache // Actual type is map[string]int64 which is "connId -> lastSeen"
	liveConnections        map[connectionId]bool
	maxLiveStreams         int
	staleConnectionTimeout time.Duration
	stats                  AssemblerStats
}

// Context
// The assembler context
type context struct {
	CaptureInfo gopacket.CaptureInfo
	Origin      api.Capture
}

func (c *context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}

func NewTcpAssembler(id string, identifyMode bool, outputChannel chan *api.OutputChannelItem, streamsMap api.TcpStreamMap, opts *misc.Opts) (*TcpAssembler, error) {
	lastClosedConnections, err := lru.NewWithEvict(lastClosedConnectionsMaxItems, func(key interface{}, value interface{}) {})

	if err != nil {
		return nil, err
	}

	a := &TcpAssembler{
		ignoredPorts:           opts.IgnoredPorts,
		lastClosedConnections:  lastClosedConnections,
		liveConnections:        make(map[connectionId]bool),
		maxLiveStreams:         opts.MaxLiveStreams,
		staleConnectionTimeout: opts.StaleConnectionTimeout,
		stats:                  AssemblerStats{},
	}

	a.streamFactory = NewTcpStreamFactory(id, identifyMode, outputChannel, streamsMap, opts, a)
	a.streamPool = reassembly.NewStreamPool(a.streamFactory)
	a.Assembler = reassembly.NewAssembler(a.streamPool)

	maxBufferedPagesTotal := GetMaxBufferedPagesPerConnection()
	maxBufferedPagesPerConnection := GetMaxBufferedPagesTotal()
	log.Info().
		Int("maxBufferedPagesTotal", maxBufferedPagesTotal).
		Int("maxBufferedPagesPerConnection", maxBufferedPagesPerConnection).
		Interface("opts", opts).
		Msg("Assembler options:")
	a.Assembler.AssemblerOptions.MaxBufferedPagesTotal = maxBufferedPagesTotal
	a.Assembler.AssemblerOptions.MaxBufferedPagesPerConnection = maxBufferedPagesPerConnection

	return a, nil
}

func (a *TcpAssembler) ProcessPackets(packets <-chan source.TcpPacketInfo) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	ticker := time.NewTicker(a.staleConnectionTimeout)
	dumpPacket := false

out:
	for {
		select {
		case packetInfo, ok := <-packets:
			if !ok {
				break out
			}
			a.ProcessPacket(packetInfo, dumpPacket)
		case <-signalChan:
			log.Info().Msg("Caught SIGINT: aborting")
			break out
		case <-ticker.C:
			a.periodicClean()
		}
	}

	closed := a.FlushAll()
	log.Debug().Int("closed", closed).Msg("Final flush.")
}

func (a *TcpAssembler) ProcessPacket(packetInfo source.TcpPacketInfo, dumpPacket bool) {
	packetsCount := diagnose.AppStats.IncPacketsCount()

	if packetsCount%packetsSeenLogThreshold == 0 {
		log.Debug().Int("count", int(packetsCount)).Msg("Packets seen:")
	}

	packet := packetInfo.Packet
	data := packet.Data()
	diagnose.AppStats.UpdateProcessedBytes(uint64(len(data)))
	if dumpPacket {
		log.Debug().Msg(fmt.Sprintf("Packet content (%d/0x%x) - %s", len(data), len(data), hex.Dump(data)))
	}

	tcp := packet.Layer(layers.LayerTypeTCP)
	if tcp != nil {
		a.processTcpPacket(packetInfo.Source.Origin, packet, tcp.(*layers.TCP))
	}
}

func (a *TcpAssembler) processTcpPacket(origin api.Capture, packet gopacket.Packet, tcp *layers.TCP) {
	diagnose.AppStats.IncTcpPacketsCount()
	if a.shouldIgnorePort(uint16(tcp.DstPort)) || a.shouldIgnorePort(uint16(tcp.SrcPort)) {
		diagnose.AppStats.IncIgnoredPacketsCount()
		return
	}

	id := getConnectionId(packet.NetworkLayer().NetworkFlow().Src().String(),
		packet.TransportLayer().TransportFlow().Src().String(),
		packet.NetworkLayer().NetworkFlow().Dst().String(),
		packet.TransportLayer().TransportFlow().Dst().String())

	if a.isRecentlyClosed(id) {
		diagnose.AppStats.IncIgnoredLastAckCount()
		return
	}

	if a.shouldThrottle(id) {
		diagnose.AppStats.IncThrottledPackets()
		return
	}

	c := context{
		CaptureInfo: packet.Metadata().CaptureInfo,
		Origin:      origin,
	}
	diagnose.InternalStats.Totalsz += len(tcp.Payload)
	a.AssembleWithContext(packet, tcp, &c)
}

func (a *TcpAssembler) tcpStreamCreated(stream *tcpStream) {
	a.lock.Lock()
	a.liveConnections[stream.connectionId] = true
	a.lock.Unlock()
}

func (a *TcpAssembler) tcpStreamClosed(stream *tcpStream) {
	a.lock.Lock()
	a.lastClosedConnections.Add(stream.connectionId, time.Now().UnixMilli())
	delete(a.liveConnections, stream.connectionId)
	a.lock.Unlock()
}

func (a *TcpAssembler) isRecentlyClosed(c connectionId) bool {
	a.lock.Lock()
	defer a.lock.Unlock()

	if closedTimeMillis, ok := a.lastClosedConnections.Get(c); ok {
		timeSinceClosed := time.Since(time.UnixMilli(closedTimeMillis.(int64)))
		if timeSinceClosed < lastAckThreshold {
			return true
		}
	}
	return false
}

func (a *TcpAssembler) shouldThrottle(c connectionId) bool {
	a.lock.Lock()
	defer a.lock.Unlock()

	if _, ok := a.liveConnections[c]; ok {
		return false
	}

	return len(a.liveConnections) > a.maxLiveStreams
}

func (a *TcpAssembler) DumpStreamPool() {
	a.streamPool.Dump()
}

func (a *TcpAssembler) WaitAndDump() {
	a.streamFactory.WaitGoRoutines()
	log.Debug().Msg(a.Dump())
}

func (a *TcpAssembler) shouldIgnorePort(port uint16) bool {
	for _, p := range a.ignoredPorts {
		if port == p {
			return true
		}
	}

	return false
}

func (a *TcpAssembler) periodicClean() {
	flushed, closed := a.FlushCloseOlderThan(time.Now().Add(-a.staleConnectionTimeout))
	stats := a.stats
	stats.ClosedConnections += closed
	stats.FlushedConnections += flushed
}

func (a *TcpAssembler) DumpStats() AssemblerStats {
	result := a.stats
	a.stats = AssemblerStats{}
	return result
}

func getConnectionId(saddr string, sport string, daddr string, dport string) connectionId {
	s := fmt.Sprintf("%s:%s", saddr, sport)
	d := fmt.Sprintf("%s:%s", daddr, dport)
	if s > d {
		return NewConnectionId(fmt.Sprintf("%s#%s", s, d))
	} else {
		return NewConnectionId(fmt.Sprintf("%s#%s", d, s))
	}
}
