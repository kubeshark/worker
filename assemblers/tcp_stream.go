package assemblers

import (
	"bufio"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/worker/misc"
	"github.com/rs/zerolog/log"
)

type tcpStreamCallbacks interface {
	tcpStreamCreated(stream *tcpStream)
	tcpStreamClosed(stream *tcpStream)
}

/* It's a connection (bidirectional)
 * Implements gopacket.reassembly.Stream interface (Accept, ReassembledSG, ReassemblyComplete)
 * ReassembledSG gets called when new reassembled data is ready (i.e. bytes in order, no duplicates, complete)
 * In our implementation, we pass information from ReassembledSG to the TcpReader through a shared channel.
 */
type tcpStream struct {
	id             int64
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
	connectionId   connectionId
	callbacks      tcpStreamCallbacks
	pcap           *os.File
	pcapWriter     *pcapgo.Writer
	sync.Mutex
}

func NewTcpStream(identifyMode bool, isTargetted bool, streamsMap api.TcpStreamMap, capture api.Capture,
	connectionId connectionId, callbacks tcpStreamCallbacks) *tcpStream {
	t := &tcpStream{
		identifyMode: identifyMode,
		isTargetted:  isTargetted,
		streamsMap:   streamsMap,
		origin:       capture,
		createdAt:    time.Now(),
		connectionId: connectionId,
		callbacks:    callbacks,
	}

	t.callbacks.tcpStreamCreated(t)

	return t
}

func (t *tcpStream) getId() int64 {
	return t.id
}

func (t *tcpStream) setId(id int64) {
	t.id = id
	log.Info().Int("id", int(t.id)).Msg("New TCP stream:")

	pcap, err := os.OpenFile(fmt.Sprintf("data/tcp_stream_%09d.pcap", id), os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Error().Err(err).Msg("Couldn't create PCAP:")
	}
	t.pcap = pcap

	t.pcapWriter = pcapgo.NewWriter(bufio.NewWriter(t.pcap))
	t.pcapWriter.WriteFileHeader(uint32(misc.Snaplen), layers.LinkTypeIPv4)
}

func (t *tcpStream) close() {
	t.Lock()
	defer t.Unlock()

	if t.isClosed {
		return
	}

	t.isClosed = true

	t.streamsMap.Delete(t.id)
	t.client.close()
	t.server.close()
	t.callbacks.tcpStreamClosed(t)

	t.pcap.Close()
	// if !t.isEmittable() {
	// 	log.Info().Str("file", t.pcap.Name()).Msg("Removing PCAP:")
	// 	os.Remove(t.pcap.Name())
	// } else {
	// 	os.Rename(t.pcap.Name(), fmt.Sprintf("data/tcp_stream_%09d.pcap", t.id))
	// }
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
	t.emittable = true
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
