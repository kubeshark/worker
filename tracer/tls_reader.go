package tracer

import (
	"io"
	"net"
	"strconv"
	"time"

	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/worker/misc"
	"github.com/rs/zerolog/log"
)

type tlsReader struct {
	key           string
	chunks        chan *tracerTlsChunk
	seenChunks    int
	data          []byte
	doneHandler   func(r *tlsReader)
	progress      *api.ReadProgress
	tcpID         *api.TcpID
	isClient      bool
	captureTime   time.Time
	extension     *api.Extension
	emitter       api.Emitter
	counterPair   *api.CounterPair
	parent        *tlsStream
	reqResMatcher api.RequestResponseMatcher
}

func (r *tlsReader) newChunk(chunk *tracerTlsChunk) {
	r.captureTime = time.Now()
	r.seenChunks = r.seenChunks + 1

	if r.parent.GetIsIdentifyMode() {
		r.writePacket(
			r.getIPv4(),
			r.getTCP(),
			gopacket.Payload(chunk.getRecordedData()),
		)
	}

	r.chunks <- chunk
}

func (r *tlsReader) Read(p []byte) (int, error) {
	var chunk *tracerTlsChunk

	for len(r.data) == 0 {
		var ok bool
		select {
		case chunk, ok = <-r.chunks:
			if !ok {
				return 0, io.EOF
			}

			r.data = chunk.getRecordedData()
		case <-time.After(time.Second * 120):
			r.doneHandler(r)
			return 0, io.EOF
		}

		if len(r.data) > 0 {
			break
		}
	}

	l := copy(p, r.data)
	r.data = r.data[l:]
	r.progress.Feed(l)

	return l, nil
}

func (r *tlsReader) GetReqResMatcher() api.RequestResponseMatcher {
	return r.reqResMatcher
}

func (r *tlsReader) GetIsClient() bool {
	return r.isClient
}

func (r *tlsReader) GetReadProgress() *api.ReadProgress {
	return r.progress
}

func (r *tlsReader) GetParent() api.TcpStream {
	return r.parent
}

func (r *tlsReader) GetTcpID() *api.TcpID {
	return r.tcpID
}

func (r *tlsReader) GetCounterPair() *api.CounterPair {
	return r.counterPair
}

func (r *tlsReader) GetCaptureTime() time.Time {
	return r.captureTime
}

func (r *tlsReader) GetEmitter() api.Emitter {
	return r.emitter
}

func (r *tlsReader) GetIsClosed() bool {
	return false
}

func (r *tlsReader) writePacket(l ...gopacket.SerializableLayer) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buf, opts, l...)
	if err != nil {
		log.Error().Err(err).Msg("Did an oopsy serializing packet:")
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Lazy)
	outgoingPacket := packet.Data()

	info := packet.Metadata().CaptureInfo
	info.Length = len(outgoingPacket)
	info.CaptureLength = len(outgoingPacket)

	err = r.parent.pcapWriter.WritePacket(info, outgoingPacket)
	if err != nil {
		log.Error().Err(err).Msg("Did an oopsy writing PCAP:")
	}
}

func (r *tlsReader) getIPv4() gopacket.SerializableLayer {
	srcIP, _, err := net.ParseCIDR(r.tcpID.SrcIP + "/24")
	if err != nil {
		panic(err)
	}
	dstIP, _, err := net.ParseCIDR(r.tcpID.DstIP + "/24")
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

func (r *tlsReader) getTCP() *layers.TCP {
	srcPort, err := strconv.ParseUint(r.tcpID.SrcPort, 10, 64)
	if err != nil {
		panic(err)
	}
	dstPort, err := strconv.ParseUint(r.tcpID.DstPort, 10, 64)
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
