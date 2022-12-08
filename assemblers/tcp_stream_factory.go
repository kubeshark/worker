package assemblers

import (
	"fmt"
	"sync"

	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/base/pkg/extensions"
	"github.com/kubeshark/worker/diagnose"
	"github.com/kubeshark/worker/misc"
	v1 "k8s.io/api/core/v1"

	"github.com/kubeshark/gopacket"
	"github.com/kubeshark/gopacket/layers" // pulls in all layers decoders
	"github.com/kubeshark/gopacket/reassembly"
	"github.com/rs/zerolog/log"
)

/*
 * The TCP factory: returns a new Stream
 * Implements gopacket.reassembly.StreamFactory interface (New)
 * Generates a new tcp stream for each new tcp connection. Closes the stream when the connection closes.
 */
type tcpStreamFactory struct {
	id               string
	wg               sync.WaitGroup
	identifyMode     bool
	outputChannel    chan *api.OutputChannelItem
	streamsMap       api.TcpStreamMap
	ownIps           []string
	opts             *misc.Opts
	streamsCallbacks tcpStreamCallbacks
}

func NewTcpStreamFactory(id string, identifyMode bool, outputChannel chan *api.OutputChannelItem, streamsMap api.TcpStreamMap, opts *misc.Opts, streamsCallbacks tcpStreamCallbacks) *tcpStreamFactory {
	var ownIps []string

	if localhostIPs, err := getLocalhostIPs(); err != nil {
		// TODO: think this over
		log.Error().Err(err).Msg("While getting self IP address!")
		ownIps = make([]string, 0)
	} else {
		ownIps = localhostIPs
	}

	return &tcpStreamFactory{
		id:               id,
		identifyMode:     identifyMode,
		outputChannel:    outputChannel,
		streamsMap:       streamsMap,
		ownIps:           ownIps,
		opts:             opts,
		streamsCallbacks: streamsCallbacks,
	}
}

func (factory *tcpStreamFactory) New(net, transport gopacket.Flow, tcpLayer *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	fsmOptions := reassembly.TCPSimpleFSMOptions{
		SupportMissingEstablishment: true,
	}
	srcIp := net.Src().String()
	dstIp := net.Dst().String()
	srcPort := transport.Src().String()
	dstPort := transport.Dst().String()

	props := factory.getStreamProps(srcIp, srcPort, dstIp, dstPort)
	isTargetted := props.isTargetted
	connectionId := getConnectionId(srcIp, srcPort, dstIp, dstPort)
	stream := NewTcpStream(factory.id, factory.identifyMode, isTargetted, factory.streamsMap, getPacketOrigin(ac), connectionId, factory.streamsCallbacks)
	var emitter api.Emitter = &api.Emitting{
		AppStats:      &diagnose.AppStats,
		Stream:        stream,
		OutputChannel: factory.outputChannel,
	}
	reassemblyStream := NewTcpReassemblyStream(fmt.Sprintf("%s:%s", net, transport), tcpLayer, fsmOptions, stream)
	if stream.GetIsTargetted() {
		stream.setId(factory.streamsMap.NextId())
		for _, extension := range extensions.Extensions {
			counterPair := &api.CounterPair{
				Request:  0,
				Response: 0,
			}
			stream.addCounterPair(counterPair)

			reqResMatcher := extension.Dissector.NewResponseRequestMatcher()
			stream.addReqResMatcher(reqResMatcher)
		}

		stream.client = NewTcpReader(
			fmt.Sprintf("%s %s", net, transport),
			&api.TcpID{
				SrcIP:   srcIp,
				DstIP:   dstIp,
				SrcPort: srcPort,
				DstPort: dstPort,
			},
			stream,
			true,
			props.isOutgoing,
			emitter,
		)

		stream.server = NewTcpReader(
			fmt.Sprintf("%s %s", net, transport),
			&api.TcpID{
				SrcIP:   net.Dst().String(),
				DstIP:   net.Src().String(),
				SrcPort: transport.Dst().String(),
				DstPort: transport.Src().String(),
			},
			stream,
			false,
			props.isOutgoing,
			emitter,
		)

		factory.streamsMap.Store(stream.getId(), stream)

		factory.wg.Add(2)
		go stream.client.run(misc.FilteringOptions, &factory.wg)
		go stream.server.run(misc.FilteringOptions, &factory.wg)
	}
	return reassemblyStream
}

func (factory *tcpStreamFactory) WaitGoRoutines() {
	factory.wg.Wait()
}

func inArrayPod(pods []v1.Pod, address string) bool {
	for _, pod := range pods {
		if pod.Status.PodIP == address {
			return true
		}
	}
	return false
}

func (factory *tcpStreamFactory) getStreamProps(srcIP string, srcPort string, dstIP string, dstPort string) *streamProps {
	if factory.opts.HostMode {
		if inArrayPod(misc.TargettedPods, fmt.Sprintf("%s:%s", dstIP, dstPort)) {
			return &streamProps{isTargetted: true, isOutgoing: false}
		} else if inArrayPod(misc.TargettedPods, dstIP) {
			return &streamProps{isTargetted: true, isOutgoing: false}
		} else if inArrayPod(misc.TargettedPods, fmt.Sprintf("%s:%s", srcIP, srcPort)) {
			return &streamProps{isTargetted: true, isOutgoing: true}
		} else if inArrayPod(misc.TargettedPods, srcIP) {
			return &streamProps{isTargetted: true, isOutgoing: true}
		}
		return &streamProps{isTargetted: false, isOutgoing: false}
	} else {
		return &streamProps{isTargetted: true}
	}
}

func getPacketOrigin(ac reassembly.AssemblerContext) api.Capture {
	c, ok := ac.(*context)

	if !ok {
		// If ac is not our context, fallback to Pcap
		return api.Pcap
	}

	return c.Origin
}

type streamProps struct {
	isTargetted bool
	isOutgoing  bool
}
