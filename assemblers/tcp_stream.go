package assemblers

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/gopacket/pcapgo"
	"github.com/kubeshark/worker/misc"
	"github.com/rs/zerolog/log"
)

/* It's a connection (bidirectional)
 * Implements gopacket.reassembly.Stream interface (Accept, ReassembledSG, ReassemblyComplete)
 * ReassembledSG gets called when new reassembled data is ready (i.e. bytes in order, no duplicates, complete)
 * In our implementation, we pass information from ReassembledSG to the TcpReader through a shared channel.
 */
type tcpStream struct {
	id             int64
	pcapId         string
	itemCount      int64
	identifyMode   bool
	emittable      bool
	isClosed       bool
	protocol       *api.Protocol
	isTargetted    bool
	client         *tcpReader
	server         *tcpReader
	origin         api.Capture
	counterPairs   []*api.CounterPair
	reqResMatchers []api.RequestResponseMatcher
	createdAt      time.Time
	streamsMap     api.TcpStreamMap
	pcap           *os.File
	pcapWriter     *pcapgo.Writer
	sync.Mutex
}

func NewTcpStream(pcapId string, identifyMode bool, isTargetted bool, streamsMap api.TcpStreamMap, capture api.Capture) *tcpStream {
	t := &tcpStream{
		pcapId:       pcapId,
		identifyMode: identifyMode,
		isTargetted:  isTargetted,
		streamsMap:   streamsMap,
		origin:       capture,
		createdAt:    time.Now(),
	}

	return t
}

func (t *tcpStream) createPcapWriter() {
	if t.GetIsIdentifyMode() {
		tmpPcapPath := misc.BuildTmpPcapPath(t.id)
		log.Info().Str("file", tmpPcapPath).Msg("Dumping TCP stream:")

		var err error
		t.pcap, err = os.OpenFile(tmpPcapPath, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Error().Err(err).Msg("Couldn't create PCAP:")
		} else {
			t.pcapWriter = pcapgo.NewWriter(t.pcap)
			t.pcapWriter.WriteFileHeader(uint32(misc.Snaplen), layers.LinkTypeLinuxSLL)
		}
	}
}

func (t *tcpStream) handlePcapDissectionResult() {
	if t.GetIsIdentifyMode() && !t.isEmittable() {
		tmpPcapPath := misc.BuildTmpPcapPath(t.id)
		log.Debug().Str("file", tmpPcapPath).Int("id", int(t.id)).Msg("Removing PCAP:")
		os.Remove(tmpPcapPath)
	}
}

func (t *tcpStream) getId() int64 {
	return t.id
}

func (t *tcpStream) setId(id int64) {
	t.id = id
	t.createPcapWriter()
}

func (t *tcpStream) close() {
	t.Lock()
	defer t.Unlock()

	if t.isClosed {
		return
	}

	t.isClosed = true

	if t.GetIsIdentifyMode() {
		log.Debug().Str("pcap", t.pcap.Name()).Msg("Closing:")
		t.pcap.Close()
	}

	t.streamsMap.Delete(t.id)
	t.client.close()
	t.server.close()
}

func (t *tcpStream) addCounterPair(counterPair *api.CounterPair) {
	t.counterPairs = append(t.counterPairs, counterPair)
}

func (t *tcpStream) addReqResMatcher(reqResMatcher api.RequestResponseMatcher) {
	t.reqResMatchers = append(t.reqResMatchers, reqResMatcher)
}

func (t *tcpStream) isProtocolIdentified() bool {
	return t.protocol != nil
}

func (t *tcpStream) isEmittable() bool {
	return t.emittable
}

func (t *tcpStream) SetProtocol(protocol *api.Protocol) {
	t.protocol = protocol

	// Clean the buffers
	t.Lock()
	t.client.msgBufferMaster = make([]api.TcpReaderDataMsg, 0)
	t.server.msgBufferMaster = make([]api.TcpReaderDataMsg, 0)
	t.Unlock()
}

func (t *tcpStream) SetAsEmittable() {
	if t.GetIsIdentifyMode() && !t.isEmittable() {
		tmpPcapPath := misc.BuildTmpPcapPath(t.id)
		log.Debug().Int("id", int(t.id)).Msg("Finalizing PCAP:")
		os.Rename(tmpPcapPath, misc.BuildPcapPath(t.id))
	}
	t.emittable = true
}

func (t *tcpStream) GetPcapId() string {
	return fmt.Sprintf("%s-%d", t.pcapId, t.itemCount)
}

func (t *tcpStream) GetIsIdentifyMode() bool {
	return t.identifyMode
}

func (t *tcpStream) GetOrigin() api.Capture {
	return t.origin
}

func (t *tcpStream) GetReqResMatchers() []api.RequestResponseMatcher {
	return t.reqResMatchers
}

func (t *tcpStream) GetIsTargetted() bool {
	return t.isTargetted
}

func (t *tcpStream) GetIsClosed() bool {
	return t.isClosed
}

func (t *tcpStream) IncrementItemCount() {
	t.itemCount++
}
