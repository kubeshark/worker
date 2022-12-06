package source

import (
	"fmt"
	"io"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/worker/diagnose"
	"github.com/kubeshark/worker/misc"
	"github.com/rs/zerolog/log"
)

type Handle interface {
	NextPacket() (packet gopacket.Packet, err error)
	SetDecoder(decoder gopacket.Decoder, lazy bool, noCopy bool)
	SetBPF(expr string) (err error)
	LinkType() layers.LinkType
	Stats() (packetsReceived uint, packetsDropped uint, err error)
	Close() (err error)
}

type tcpPacketSource struct {
	Handle    Handle
	defragger *ip4defrag.IPv4Defragmenter
	name      string
	Origin    api.Capture
}

type TcpPacketInfo struct {
	Packet gopacket.Packet
	Source *tcpPacketSource
}

func NewTcpPacketSource(name, filename string, interfaceName string, packetCapture string,
	origin api.Capture) (*tcpPacketSource, error) {
	var err error

	result := &tcpPacketSource{
		name:      name,
		defragger: ip4defrag.NewIPv4Defragmenter(),
		Origin:    origin,
	}

	targetSizeMb := 8
	promisc := true
	tstype := ""
	lazy := false

	switch packetCapture {
	case "af_packet":
		result.Handle, err = newAfpacketHandle(
			interfaceName,
			targetSizeMb,
			misc.Snaplen,
		)
		if err != nil {
			return nil, err
		}
		log.Info().Msg("Using AF_PACKET socket as the capture source")
	default:
		result.Handle, err = newPcapHandle(
			filename,
			interfaceName,
			misc.Snaplen,
			promisc,
			tstype,
		)
		if err != nil {
			return nil, err
		}
		log.Info().Msg("Using libpcap as the capture source")
	}

	var decoder gopacket.Decoder
	if filename == "" {
		var ok bool
		decoderName := result.Handle.LinkType().String()
		if decoder, ok = gopacket.DecodersByLayerName[decoderName]; !ok {
			return nil, fmt.Errorf("no decoder named %v", decoderName)
		}
	} else {
		decoder = gopacket.DecodePayload
	}

	result.Handle.SetDecoder(decoder, lazy, true)

	return result, nil
}

func (source *tcpPacketSource) String() string {
	return source.name
}

func (source *tcpPacketSource) setBPFFilter(expr string) (err error) {
	return source.Handle.SetBPF(expr)
}

func (source *tcpPacketSource) close() {
	if source.Handle != nil {
		source.Handle.Close()
	}
}

func (source *tcpPacketSource) Stats() (packetsReceived uint, packetsDropped uint, err error) {
	return source.Handle.Stats()
}

func (source *tcpPacketSource) ReadPackets(packets chan<- TcpPacketInfo) {
	log.Info().Str("source", source.name).Msg("Start reading packets from:")

	for {
		packet, err := source.Handle.NextPacket()

		if err == io.EOF {
			log.Info().Str("source", source.name).Msg("Got EOF while reading packets from:")
			close(packets)
			log.Info().Str("source", source.name).Msg("Closed packet channel because of EOF.")
			return
		} else if err != nil {
			if err.Error() != "Timeout Expired" {
				log.Debug().Err(err).Str("source", source.name).Msg("While reading from:")
			}
			continue
		}

		// defrag the IPv4 packet if required
		if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
			ip4 := ip4Layer.(*layers.IPv4)
			l := ip4.Length
			newip4, err := source.defragger.DefragIPv4(ip4)
			if err != nil {
				log.Debug().Err(err).Msg("While de-fragmenting!")
				continue
			} else if newip4 == nil {
				log.Debug().Msg("Fragment...")
				continue // packet fragment, we don't have whole packet yet.
			}
			if newip4.Length != l {
				diagnose.InternalStats.Ipdefrag++
				log.Debug().Int("layer-type", int(newip4.NextLayerType())).Msg("Decoding re-assembled packet:")
				pb, ok := packet.(gopacket.PacketBuilder)
				if !ok {
					log.Debug().Msg("Not a PacketBuilder")
				}
				nextDecoder := newip4.NextLayerType()
				_ = nextDecoder.Decode(newip4.Payload, pb)
			}
		}

		packets <- TcpPacketInfo{
			Packet: packet,
			Source: source,
		}
	}
}
