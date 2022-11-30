package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/kubeshark/base/pkg/api"
	v1 "k8s.io/api/core/v1"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers" // pulls in all layers decoders
	"github.com/google/gopacket/reassembly"
)

/*
 * The TCP factory: returns a new Stream
 * Implements gopacket.reassembly.StreamFactory interface (New)
 * Generates a new tcp stream for each new tcp connection. Closes the stream when the connection closes.
 */
type tcpStreamFactory struct {
	wg               sync.WaitGroup
	emitter          api.Emitter
	streamsMap       api.TcpStreamMap
	ownIps           []string
	opts             *Opts
	streamsCallbacks tcpStreamCallbacks
}

func NewTcpStreamFactory(emitter api.Emitter, streamsMap api.TcpStreamMap, opts *Opts, streamsCallbacks tcpStreamCallbacks) *tcpStreamFactory {
	var ownIps []string

	if localhostIPs, err := getLocalhostIPs(); err != nil {
		// TODO: think this over
		log.Print("Failed to get self IP addresses")
		log.Printf("Getting-Self-Address. Error getting self ip address: %v (%v,%+v)", err, err, err)
		ownIps = make([]string, 0)
	} else {
		ownIps = localhostIPs
	}

	return &tcpStreamFactory{
		emitter:          emitter,
		streamsMap:       streamsMap,
		ownIps:           ownIps,
		opts:             opts,
		streamsCallbacks: streamsCallbacks,
	}
}

func (factory *tcpStreamFactory) New(net, transport gopacket.Flow, tcpLayer *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	fsmOptions := reassembly.TCPSimpleFSMOptions{
		SupportMissingEstablishment: *allowmissinginit,
	}
	srcIp := net.Src().String()
	dstIp := net.Dst().String()
	srcPort := transport.Src().String()
	dstPort := transport.Dst().String()

	props := factory.getStreamProps(srcIp, srcPort, dstIp, dstPort)
	isTargetted := props.isTargetted
	connectionId := getConnectionId(srcIp, srcPort, dstIp, dstPort)
	stream := NewTcpStream(isTargetted, factory.streamsMap, getPacketOrigin(ac), connectionId, factory.streamsCallbacks)
	reassemblyStream := NewTcpReassemblyStream(fmt.Sprintf("%s:%s", net, transport), tcpLayer, fsmOptions, stream)
	if stream.GetIsTargetted() {
		stream.setId(factory.streamsMap.NextId())
		for _, extension := range extensions {
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
			factory.emitter,
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
			factory.emitter,
		)

		factory.streamsMap.Store(stream.getId(), stream)

		factory.wg.Add(2)
		go stream.client.run(filteringOptions, &factory.wg)
		go stream.server.run(filteringOptions, &factory.wg)
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
		if inArrayPod(targettedPods, fmt.Sprintf("%s:%s", dstIP, dstPort)) {
			return &streamProps{isTargetted: true, isOutgoing: false}
		} else if inArrayPod(targettedPods, dstIP) {
			return &streamProps{isTargetted: true, isOutgoing: false}
		} else if inArrayPod(targettedPods, fmt.Sprintf("%s:%s", srcIP, srcPort)) {
			return &streamProps{isTargetted: true, isOutgoing: true}
		} else if inArrayPod(targettedPods, srcIP) {
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
