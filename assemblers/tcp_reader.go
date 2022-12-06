package assemblers

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/protos"
	"github.com/rs/zerolog/log"
)

/* TcpReader gets reads from a channel of bytes of tcp payload, and parses it into requests and responses.
 * The payload is written to the channel by a tcpStream object that is dedicated to one tcp connection.
 * An TcpReader object is unidirectional: it parses either a client stream or a server stream.
 * Implements io.Reader interface (Read)
 */
type tcpReader struct {
	ident           string
	tcpID           *api.TcpID
	isClosed        bool
	isClient        bool
	isOutgoing      bool
	msgQueue        chan api.TcpReaderDataMsg // Channel of captured reassembled tcp payload
	msgBuffer       []api.TcpReaderDataMsg
	msgBufferMaster []api.TcpReaderDataMsg
	data            []byte
	progress        *api.ReadProgress
	captureTime     time.Time
	parent          *tcpStream
	emitter         api.Emitter
	counterPair     *api.CounterPair
	reqResMatcher   api.RequestResponseMatcher
	sync.Mutex
}

func NewTcpReader(ident string, tcpId *api.TcpID, parent *tcpStream, isClient bool, isOutgoing bool, emitter api.Emitter) *tcpReader {
	return &tcpReader{
		msgQueue:   make(chan api.TcpReaderDataMsg),
		progress:   &api.ReadProgress{},
		ident:      ident,
		tcpID:      tcpId,
		parent:     parent,
		isClient:   isClient,
		isOutgoing: isOutgoing,
		emitter:    emitter,
	}
}

func (reader *tcpReader) run(options *api.TrafficFilteringOptions, wg *sync.WaitGroup) {
	defer wg.Done()

	for i, extension := range protos.Extensions {
		reader.reqResMatcher = reader.parent.reqResMatchers[i]
		reader.counterPair = reader.parent.counterPairs[i]
		b := bufio.NewReader(reader)
		extension.Dissector.Dissect(b, reader, options) //nolint
		if reader.isProtocolIdentified() {
			break
		}
		reader.rewind()
	}
}

func (reader *tcpReader) close() {
	reader.Lock()
	if !reader.isClosed {
		reader.isClosed = true
		close(reader.msgQueue)
	}
	reader.Unlock()
}

func (reader *tcpReader) sendMsgIfNotClosed(msg api.TcpReaderDataMsg) {
	reader.Lock()
	if !reader.isClosed {
		reader.msgQueue <- msg
	}
	reader.Unlock()
}

func (reader *tcpReader) isProtocolIdentified() bool {
	return reader.parent.protocol != nil
}

func (reader *tcpReader) rewind() {
	// Reset the data
	reader.data = make([]byte, 0)

	// Reset msgBuffer from the master record
	reader.parent.Lock()
	reader.msgBuffer = make([]api.TcpReaderDataMsg, len(reader.msgBufferMaster))
	copy(reader.msgBuffer, reader.msgBufferMaster)
	reader.parent.Unlock()

	// Reset the read progress
	reader.progress.Reset()
}

func (reader *tcpReader) populateData(msg api.TcpReaderDataMsg) {
	reader.data = msg.GetBytes()
	reader.captureTime = msg.GetTimestamp()
}

func (reader *tcpReader) Read(p []byte) (int, error) {
	var msg api.TcpReaderDataMsg

	for len(reader.msgBuffer) > 0 && len(reader.data) == 0 {
		// Pop first message
		if len(reader.msgBuffer) > 1 {
			msg, reader.msgBuffer = reader.msgBuffer[0], reader.msgBuffer[1:]
		} else {
			msg = reader.msgBuffer[0]
			reader.msgBuffer = make([]api.TcpReaderDataMsg, 0)
		}

		// Get the bytes
		reader.populateData(msg)
	}

	ok := true
	for ok && len(reader.data) == 0 {
		msg, ok = <-reader.msgQueue
		if msg != nil {
			reader.populateData(msg)

			if reader.parent.GetIsIdentifyMode() {
				log.Debug().Int("id", int(reader.parent.id)).Msg("Writing packet:")
				reader.writePacket(
					reader.getIP(),
					reader.getTCP(),
					gopacket.Payload(reader.data),
				)
			}

			if !reader.isProtocolIdentified() {
				reader.msgBufferMaster = append(
					reader.msgBufferMaster,
					msg,
				)
			}
		}
	}

	if !ok || len(reader.data) == 0 {
		if reader.parent.GetIsIdentifyMode() {
			reader.parent.pcap.Close()
			if !reader.parent.isEmittable() {
				log.Debug().Str("file", reader.parent.pcap.Name()).Int("id", int(reader.parent.id)).Msg("Removing PCAP:")
				os.Remove(reader.parent.pcap.Name())
			} else {
				log.Debug().Int("id", int(reader.parent.id)).Msg("Finalizing PCAP:")
				os.Rename(reader.parent.pcap.Name(), fmt.Sprintf("data/tcp_stream_%09d.pcap", reader.parent.id))
			}
		}

		return 0, io.EOF
	}

	l := copy(p, reader.data)
	reader.data = reader.data[l:]
	reader.progress.Feed(l)

	return l, nil
}

func (reader *tcpReader) GetReqResMatcher() api.RequestResponseMatcher {
	return reader.reqResMatcher
}

func (reader *tcpReader) GetIsClient() bool {
	return reader.isClient
}

func (reader *tcpReader) GetReadProgress() *api.ReadProgress {
	return reader.progress
}

func (reader *tcpReader) GetParent() api.TcpStream {
	return reader.parent
}

func (reader *tcpReader) GetTcpID() *api.TcpID {
	return reader.tcpID
}

func (reader *tcpReader) GetCounterPair() *api.CounterPair {
	return reader.counterPair
}

func (reader *tcpReader) GetCaptureTime() time.Time {
	return reader.captureTime
}

func (reader *tcpReader) GetEmitter() api.Emitter {
	return reader.emitter
}

func (reader *tcpReader) GetIsClosed() bool {
	return reader.isClosed
}

func (reader *tcpReader) writePacket(layers ...gopacket.SerializableLayer) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buf, opts, layers...)
	if err != nil {
		log.Error().Err(err).Msg("Did an oopsy serializing packet:")
	}
	ci := gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		CaptureLength:  len(buf.Bytes()),
		Length:         len(buf.Bytes()),
		InterfaceIndex: 0,
	}

	err = reader.parent.pcapWriter.WritePacket(ci, buf.Bytes())
	if err != nil {
		log.Error().Err(err).Msg("Did an oopsy writing PCAP:")
	}
}

func (reader *tcpReader) getIP() gopacket.SerializableLayer {
	srcIP, _, err := net.ParseCIDR(reader.tcpID.SrcIP + "/24")
	if err != nil {
		panic(err)
	}
	dstIP, _, err := net.ParseCIDR(reader.tcpID.DstIP + "/24")
	if err != nil {
		panic(err)
	}
	res := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}
	return res
}

func (reader *tcpReader) getTCP() *layers.TCP {
	srcPort, err := strconv.ParseUint(reader.tcpID.SrcPort, 10, 64)
	if err != nil {
		panic(err)
	}
	dstPort, err := strconv.ParseUint(reader.tcpID.DstPort, 10, 64)
	if err != nil {
		panic(err)
	}
	return &layers.TCP{
		Window:  uint16(misc.Snaplen - 1),
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
		PSH:     false,
		ACK:     true,
		Seq:     1,
		Ack:     1,
	}
}
