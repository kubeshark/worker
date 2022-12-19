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

type tlsLayers struct {
	ethernet *layers.Ethernet
	ipv4     *layers.IPv4
	tcp      *layers.TCP
}

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
	layers        *tlsLayers
}

func (r *tlsReader) newChunk(chunk *tracerTlsChunk) {
	r.captureTime = time.Now()
	r.seenChunks = r.seenChunks + 1

	data := chunk.getRecordedData()

	r.setLayers(data)
	r.writePacket(
		layers.LayerTypeEthernet,
		r.layers.ethernet,
		r.layers.ipv4,
		r.layers.tcp,
		gopacket.Payload(data),
	)

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

func (r *tlsReader) writePacket(firstLayerType gopacket.LayerType, l ...gopacket.SerializableLayer) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	err := gopacket.SerializeLayers(buf, opts, l...)
	if err != nil {
		log.Error().Err(err).Msg("Did an oopsy serializing packet:")
	}

	packet := gopacket.NewPacket(buf.Bytes(), firstLayerType, gopacket.Lazy)
	outgoingPacket := packet.Data()

	info := packet.Metadata().CaptureInfo
	info.Length = len(outgoingPacket)
	info.CaptureLength = len(outgoingPacket)

	if r.parent.pcapWriter == nil {
		log.Debug().Msg("PCAP writer for this TLS stream does not exist (too many open files)!")
		return
	}

	err = r.parent.pcapWriter.WritePacket(info, outgoingPacket)
	if err != nil {
		log.Error().Err(err).Msg("Did an oopsy writing PCAP:")
	}
}

func (r *tlsReader) doTcpSeqAckWalk(data []byte) {
	if r.layers != nil {
		if r.isClient {
			r.layers.tcp.Ack += uint32(len(data))
		} else {
			r.layers.tcp.Seq = r.layers.tcp.Ack
		}
		return
	}
}

func (r *tlsReader) setLayers(data []byte) {
	r.doTcpSeqAckWalk(data)

	r.layers = &tlsLayers{
		ethernet: r.getEthernet(),
		ipv4:     r.getIPv4(),
		tcp:      r.getTCP(),
	}
}

func (r *tlsReader) getEthernet() *layers.Ethernet {
	srcMac, _ := net.ParseMAC("00:00:5e:00:53:01")
	dstMac, _ := net.ParseMAC("00:00:5e:00:53:02")
	res := &layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	return res
}

func (r *tlsReader) getIPv4() *layers.IPv4 {
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
		Ack:     0,
	}
}
