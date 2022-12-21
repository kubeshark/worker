package tracer

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/gopacket/pcapgo"
	"github.com/kubeshark/worker/misc"
	"github.com/rs/zerolog/log"
)

type tlsLayers struct {
	ethernet *layers.Ethernet
	ipv4     *layers.IPv4
	tcp      *layers.TCP
}

func (l *tlsLayers) swap() {
	l.ipv4.SrcIP, l.ipv4.DstIP = l.ipv4.DstIP, l.ipv4.SrcIP
	l.tcp.SrcPort, l.tcp.DstPort = l.tcp.DstPort, l.tcp.SrcPort
}

type tlsStream struct {
	poller         *tlsPoller
	key            string
	closeCounter   uint32
	id             int64
	pcapId         string
	itemCount      int64
	emittable      bool
	isClosed       bool
	client         *tlsReader
	server         *tlsReader
	reqResMatchers []api.RequestResponseMatcher
	protocol       *api.Protocol
	streamsMap     api.TcpStreamMap
	pcap           *os.File
	pcapWriter     *pcapgo.Writer
	layers         *tlsLayers
	sync.Mutex
}

func NewTlsStream(poller *tlsPoller, key string, streamsMap api.TcpStreamMap) *tlsStream {
	return &tlsStream{
		poller:     poller,
		key:        key,
		streamsMap: streamsMap,
	}
}

func (t *tlsStream) addReqResMatcher(reqResMatcher api.RequestResponseMatcher) {
	t.reqResMatchers = append(t.reqResMatchers, reqResMatcher)
}

func (t *tlsStream) createPcapWriter() {
	tmpPcapPath := misc.BuildTlsTmpPcapPath(t.id)
	log.Debug().Str("file", tmpPcapPath).Msg("Dumping TLS stream:")

	var err error
	t.pcap, err = os.OpenFile(tmpPcapPath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Error().Err(err).Msg("Couldn't create PCAP (TLS):")
	} else {
		t.pcapWriter = pcapgo.NewWriter(t.pcap)
		err = t.pcapWriter.WriteFileHeader(uint32(misc.Snaplen), layers.LinkTypeEthernet)
		if err != nil {
			log.Error().Err(err).Msg("While writing the PCAP header:")
		}
	}
}

func (t *tlsStream) getId() int64 {
	return t.id
}

func (t *tlsStream) setId(id int64) {
	t.id = id
	t.createPcapWriter()
}

func (t *tlsStream) close() {
	t.Lock()
	defer t.Unlock()

	t.closeCounter++
	if t.closeCounter < 2 {
		return
	}

	if t.isClosed {
		return
	}

	t.isClosed = true

	if t.pcap != nil {
		log.Debug().Str("pcap", t.pcap.Name()).Msg("Closing:")
		t.pcap.Close()
		pcapPath := misc.BuildPcapPath(t.id)
		misc.AlivePcaps.Delete(pcapPath)
	}

	t.streamsMap.Delete(t.id)
	t.poller.closeStreams <- t.key
}

func (t *tlsStream) isEmittable() bool {
	return t.emittable
}

func (t *tlsStream) SetProtocol(protocol *api.Protocol) {
	t.protocol = protocol
}

func (t *tlsStream) SetAsEmittable() {
	if !t.isEmittable() {
		tmpPcapPath := misc.BuildTlsTmpPcapPath(t.id)
		pcapPath := misc.BuildTlsPcapPath(t.id)
		misc.AlivePcaps.Store(pcapPath, true)
		log.Debug().Str("old", tmpPcapPath).Str("new", pcapPath).Msg("Renaming PCAP:")
		err := os.Rename(tmpPcapPath, pcapPath)
		if err != nil {
			log.Error().Err(err).Str("pcap", tmpPcapPath).Msg("Couldn't rename the PCAP file:")
		}
	}
	t.emittable = true
}

func (t *tlsStream) GetPcapId() string {
	return fmt.Sprintf("%s-%d", t.pcapId, t.itemCount)
}

func (t *tlsStream) GetIsIdentifyMode() bool {
	return true
}

func (t *tlsStream) GetReqResMatchers() []api.RequestResponseMatcher {
	return t.reqResMatchers
}

func (t *tlsStream) GetIsTargetted() bool {
	return true
}

func (t *tlsStream) GetIsClosed() bool {
	return t.isClosed
}

func (t *tlsStream) IncrementItemCount() {
	t.itemCount++
}

func (t *tlsStream) doTcpHandshake() {
	data := []byte{}

	// SYN
	t.layers.tcp.SYN = true
	t.writeLayers(data, true, 0)

	// SYN-ACK
	t.layers.swap()
	t.layers.tcp.ACK = true
	t.layers.tcp.Ack++
	t.writeLayers(data, false, 0)

	// ACK
	t.layers.swap()
	t.layers.tcp.SYN = false
	t.layers.tcp.ACK = true
	t.layers.tcp.Seq++
	t.writeLayers(data, true, 0)

	t.client.seqNumbers.Seq = 1
	t.client.seqNumbers.Ack = 1
	t.server.seqNumbers.Seq = 1
	t.server.seqNumbers.Ack = 1
}

func (t *tlsStream) writeData(data []byte, reader *tlsReader) {
	t.setLayers(data, reader)
	t.layers.tcp.ACK = true
	if reader.isClient {
		t.layers.tcp.PSH = true
	} else {
		t.layers.tcp.PSH = false
	}
	sentLen := uint32(len(data))
	t.loadSecNumbers(reader.isClient)
	t.writeLayers(data, reader.isClient, sentLen)
	t.layers.tcp.PSH = false
	t.layers.swap()
	t.loadSecNumbers(!reader.isClient)
	t.writeLayers([]byte{}, !reader.isClient, 0)
}

func (t *tlsStream) writeLayers(data []byte, isClient bool, sentLen uint32) {
	t.writePacket(
		layers.LayerTypeEthernet,
		t.layers.ethernet,
		t.layers.ipv4,
		t.layers.tcp,
		gopacket.Payload(data),
	)
	t.doTcpSeqAckWalk(isClient, sentLen)
}

func (t *tlsStream) writePacket(firstLayerType gopacket.LayerType, l ...gopacket.SerializableLayer) {
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

	if t.pcapWriter == nil {
		log.Debug().Msg("PCAP writer for this TLS stream does not exist (too many open files)!")
		return
	}

	err = t.pcapWriter.WritePacket(info, outgoingPacket)
	if err != nil {
		log.Error().Err(err).Msg("Did an oopsy writing PCAP:")
	}
}

func (t *tlsStream) loadSecNumbers(isClient bool) {
	var reader *tlsReader
	if isClient {
		reader = t.client
	} else {
		reader = t.server
	}

	t.layers.tcp.Seq = reader.seqNumbers.Seq
	t.layers.tcp.Ack = reader.seqNumbers.Ack
}

func (t *tlsStream) doTcpSeqAckWalk(isClient bool, sentLen uint32) {
	if isClient {
		t.client.seqNumbers.Seq += sentLen
		t.server.seqNumbers.Ack += sentLen
	} else {
		t.server.seqNumbers.Seq += sentLen
		t.client.seqNumbers.Ack += sentLen
	}
}

func (t *tlsStream) setLayers(data []byte, reader *tlsReader) {
	if t.layers == nil {
		t.layers = &tlsLayers{
			ethernet: t.getEthernet(),
			ipv4:     t.getIPv4(reader),
			tcp:      t.getTCP(reader),
		}
		t.doTcpHandshake()
	} else {
		ipv4 := t.getIPv4(reader)
		t.layers.ipv4.SrcIP = ipv4.SrcIP
		t.layers.ipv4.DstIP = ipv4.DstIP

		tcp := t.getTCP(reader)
		t.layers.tcp.SrcPort = tcp.SrcPort
		t.layers.tcp.DstPort = tcp.DstPort
	}
}

func (t *tlsStream) getEthernet() *layers.Ethernet {
	srcMac, _ := net.ParseMAC("00:00:5e:00:53:01")
	dstMac, _ := net.ParseMAC("00:00:5e:00:53:02")
	res := &layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	return res
}

func (t *tlsStream) getIPv4(reader *tlsReader) *layers.IPv4 {
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

func (t *tlsStream) getTCP(reader *tlsReader) *layers.TCP {
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
		SYN:     false,
		PSH:     false,
		ACK:     false,
		Seq:     0,
		Ack:     0,
	}
}
