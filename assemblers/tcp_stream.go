package assemblers

import (
	"bufio"
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
	idLong         string
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

func NewTcpStream(id string, identifyMode bool, isTargetted bool, streamsMap api.TcpStreamMap, capture api.Capture) *tcpStream {
	t := &tcpStream{
		idLong:       id,
		identifyMode: identifyMode,
		isTargetted:  isTargetted,
		streamsMap:   streamsMap,
		origin:       capture,
		createdAt:    time.Now(),
	}

	return t
}

func (t *tcpStream) getId() int64 {
	return t.id
}

func (t *tcpStream) setId(id int64) {
	t.id = id

	if t.GetIsIdentifyMode() {
		log.Info().Int("id", int(t.id)).Msg("New TCP stream:")

		pcap, err := os.OpenFile(fmt.Sprintf("data/tcp_stream_%09d.pcaptmp", id), os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Error().Err(err).Msg("Couldn't create PCAP:")
		}
		t.pcap = pcap

		t.pcapWriter = pcapgo.NewWriter(bufio.NewWriter(t.pcap))
		t.pcapWriter.WriteFileHeader(uint32(misc.Snaplen), layers.LinkTypeLinuxSLL)
	}
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

func (t *tcpStream) GetId() string {
	return t.idLong
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
