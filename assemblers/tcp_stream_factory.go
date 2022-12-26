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
	pcapId        string
	identifyMode  bool
	outputChannel chan *api.OutputChannelItem
	streamsMap    api.TcpStreamMap
	ownIps        []string
	opts          *misc.Opts
}

func NewTcpStreamFactory(pcapId string, identifyMode bool, outputChannel chan *api.OutputChannelItem, streamsMap api.TcpStreamMap, opts *misc.Opts) *tcpStreamFactory {
	var ownIps []string

	if localhostIPs, err := getLocalhostIPs(); err != nil {
		// TODO: think this over
		log.Error().Err(err).Msg("While getting self IP address!")
		ownIps = make([]string, 0)
	} else {
		ownIps = localhostIPs
	}

	return &tcpStreamFactory{
		pcapId:        pcapId,
		identifyMode:  identifyMode,
		outputChannel: outputChannel,
		streamsMap:    streamsMap,
		ownIps:        ownIps,
		opts:          opts,
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
	stream := NewTcpStream(factory.pcapId, factory.identifyMode, isTargetted, factory.streamsMap)
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

		var wg sync.WaitGroup
		wg.Add(2)
		go stream.client.run(misc.FilteringOptions, &wg)
		go stream.server.run(misc.FilteringOptions, &wg)
		go factory.waitGoRoutines(stream, &wg)
	}
	return reassemblyStream
}

func (factory *tcpStreamFactory) waitGoRoutines(stream *tcpStream, wg *sync.WaitGroup) {
	wg.Wait()
	stream.handlePcapDissectionResult()
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
	if factory.opts.ClusterMode {
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

type streamProps struct {
	isTargetted bool
	isOutgoing  bool
}
