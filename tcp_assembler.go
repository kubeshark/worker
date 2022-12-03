package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/worker/diagnose"
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
	flushedConnections int
	closedConnections  int
}

type tcpAssembler struct {
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

func NewTcpAssembler(identifyMode bool, outputChannel chan *api.OutputChannelItem, streamsMap api.TcpStreamMap, opts *Opts) (*tcpAssembler, error) {
	lastClosedConnections, err := lru.NewWithEvict(lastClosedConnectionsMaxItems, func(key interface{}, value interface{}) {})

	if err != nil {
		return nil, err
	}

	a := &tcpAssembler{
		ignoredPorts:           opts.IgnoredPorts,
		lastClosedConnections:  lastClosedConnections,
		liveConnections:        make(map[connectionId]bool),
		maxLiveStreams:         opts.maxLiveStreams,
		staleConnectionTimeout: opts.staleConnectionTimeout,
		stats:                  AssemblerStats{},
	}

	a.streamFactory = NewTcpStreamFactory(identifyMode, outputChannel, streamsMap, opts, a)
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

func (a *tcpAssembler) processPackets(dumpPacket bool, packets <-chan source.TcpPacketInfo) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	ticker := time.NewTicker(a.staleConnectionTimeout)

out:
	for {
		select {
		case packetInfo, ok := <-packets:
			if !ok {
				break out
			}
			if a.processPacket(packetInfo, dumpPacket) {
				break out
			}
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

func (a *tcpAssembler) processPacket(packetInfo source.TcpPacketInfo, dumpPacket bool) bool {
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

	done := *maxcount > 0 && int64(diagnose.AppStats.PacketsCount) >= *maxcount
	if done {
		errorMapLen, _ := diagnose.ErrorsMap.GetErrorsSummary()
		log.Info().Msg(
			fmt.Sprintf(
				"Processed %v packets (%v bytes) in %v (errors: %v, errTypes:%v)",
				diagnose.AppStats.PacketsCount,
				diagnose.AppStats.ProcessedBytes,
				time.Since(diagnose.AppStats.StartTime),
				diagnose.ErrorsMap.ErrorsCount,
				errorMapLen,
			))
	}
	return done
}

func (a *tcpAssembler) processTcpPacket(origin api.Capture, packet gopacket.Packet, tcp *layers.TCP) {
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
	a.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &c)
}

func (a *tcpAssembler) tcpStreamCreated(stream *tcpStream) {
	a.lock.Lock()
	a.liveConnections[stream.connectionId] = true
	a.lock.Unlock()
}

func (a *tcpAssembler) tcpStreamClosed(stream *tcpStream) {
	a.lock.Lock()
	a.lastClosedConnections.Add(stream.connectionId, time.Now().UnixMilli())
	delete(a.liveConnections, stream.connectionId)
	a.lock.Unlock()
}

func (a *tcpAssembler) isRecentlyClosed(c connectionId) bool {
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

func (a *tcpAssembler) shouldThrottle(c connectionId) bool {
	a.lock.Lock()
	defer a.lock.Unlock()

	if _, ok := a.liveConnections[c]; ok {
		return false
	}

	return len(a.liveConnections) > a.maxLiveStreams
}

func (a *tcpAssembler) dumpStreamPool() {
	a.streamPool.Dump()
}

func (a *tcpAssembler) waitAndDump() {
	a.streamFactory.WaitGoRoutines()
	log.Debug().Msg(a.Dump())
}

func (a *tcpAssembler) shouldIgnorePort(port uint16) bool {
	for _, p := range a.ignoredPorts {
		if port == p {
			return true
		}
	}

	return false
}

func (a *tcpAssembler) periodicClean() {
	flushed, closed := a.FlushCloseOlderThan(time.Now().Add(-a.staleConnectionTimeout))
	stats := a.stats
	stats.closedConnections += closed
	stats.flushedConnections += flushed
}

func (a *tcpAssembler) DumpStats() AssemblerStats {
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
