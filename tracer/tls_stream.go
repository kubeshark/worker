package tracer

import (
	"fmt"
	"os"

	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/gopacket/layers"
	"github.com/kubeshark/gopacket/pcapgo"
	"github.com/kubeshark/worker/misc"
	"github.com/rs/zerolog/log"
)

type tlsStream struct {
	id           int64
	pcapId       string
	itemCount    int64
	identifyMode bool
	emittable    bool
	reader       *tlsReader
	protocol     *api.Protocol
	pcap         *os.File
	pcapWriter   *pcapgo.Writer
}

func NewTlsStream() *tlsStream {
	return &tlsStream{
		identifyMode: true,
	}
}

func (t *tlsStream) createPcapWriter() {
	if t.GetIsIdentifyMode() {
		tmpPcapPath := misc.BuildTlsTmpPcapPath(t.id)
		log.Debug().Str("file", tmpPcapPath).Msg("Dumping TLS stream:")

		var err error
		t.pcap, err = os.OpenFile(tmpPcapPath, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Error().Err(err).Msg("Couldn't create PCAP (TLS):")
		} else {
			t.pcapWriter = pcapgo.NewWriter(t.pcap)
			err = t.pcapWriter.WriteFileHeader(uint32(misc.Snaplen), layers.LinkTypeIPv4)
			if err != nil {
				log.Error().Err(err).Msg("While writing the PCAP header:")
			}
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

func (t *tlsStream) isEmittable() bool {
	return t.emittable
}

func (t *tlsStream) SetProtocol(protocol *api.Protocol) {
	t.protocol = protocol
}

func (t *tlsStream) SetAsEmittable() {
	if t.GetIsIdentifyMode() && !t.isEmittable() {
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
	return t.identifyMode
}

func (t *tlsStream) GetReqResMatchers() []api.RequestResponseMatcher {
	return []api.RequestResponseMatcher{t.reader.reqResMatcher}
}

func (t *tlsStream) GetIsTargetted() bool {
	return true
}

func (t *tlsStream) GetIsClosed() bool {
	return false
}

func (t *tlsStream) IncrementItemCount() {
	t.itemCount++
}
