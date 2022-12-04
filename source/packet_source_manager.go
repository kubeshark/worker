package source

import (
	"fmt"
	"strings"

	"github.com/kubeshark/base/pkg/api"
	"github.com/rs/zerolog/log"
	v1 "k8s.io/api/core/v1"
)

const bpfFilterMaxPods = 150
const hostSourcePid = "0"

type PacketSourceManagerConfig struct {
	mtls          bool
	procfs        string
	interfaceName string
	packetCapture string
}

type PacketSourceManager struct {
	sources map[string]*tcpPacketSource
	config  PacketSourceManagerConfig
}

func NewPacketSourceManager(procfs string, interfaceName string,
	mtls bool, pods []v1.Pod,
	packetCapture string, packets chan<- TcpPacketInfo) (*PacketSourceManager, error) {
	hostSource, err := newHostPacketSource(interfaceName, packetCapture)
	if err != nil {
		return nil, err
	}

	sourceManager := &PacketSourceManager{
		sources: map[string]*tcpPacketSource{
			hostSourcePid: hostSource,
		},
	}

	sourceManager.config = PacketSourceManagerConfig{
		mtls:          mtls,
		procfs:        procfs,
		interfaceName: interfaceName,
		packetCapture: packetCapture,
	}

	go hostSource.ReadPackets(packets)
	return sourceManager, nil
}

func newHostPacketSource(interfaceName string, packetCapture string) (*tcpPacketSource, error) {
	source, err := NewTcpPacketSource(fmt.Sprintf("host-%s", interfaceName), "", interfaceName, packetCapture, api.Pcap)
	if err != nil {
		return nil, err
	}

	return source, nil
}

func (m *PacketSourceManager) UpdatePods(pods []v1.Pod, packets chan<- TcpPacketInfo) {
	if m.config.mtls {
		m.updateMtlsPods(m.config.procfs, pods, m.config.interfaceName, m.config.packetCapture, packets)
	}

	m.setBPFFilter(pods)
}

func (m *PacketSourceManager) updateMtlsPods(procfs string, pods []v1.Pod,
	interfaceName string, packetCapture string, packets chan<- TcpPacketInfo) {

	relevantPids := m.getRelevantPids(procfs, pods)
	log.Info().Msg(fmt.Sprintf("Updating mtls pods (new: %v) (current: %v)", relevantPids, m.sources))

	for pid, src := range m.sources {
		if _, ok := relevantPids[pid]; !ok {
			src.close()
			delete(m.sources, pid)
		}
	}

	for pid, origin := range relevantPids {
		if _, ok := m.sources[pid]; !ok {
			source, err := newNetnsPacketSource(procfs, pid, interfaceName, packetCapture, origin)

			if err == nil {
				go source.ReadPackets(packets)
				m.sources[pid] = source
			}
		}
	}
}

func (m *PacketSourceManager) getRelevantPids(procfs string, pods []v1.Pod) map[string]api.Capture {
	relevantPids := make(map[string]api.Capture)
	relevantPids[hostSourcePid] = api.Pcap

	if envoyPids, err := discoverRelevantEnvoyPids(procfs, pods); err != nil {
		log.Warn().Msg(fmt.Sprintf("Unable to discover envoy pids - %v", err))
	} else {
		for _, pid := range envoyPids {
			relevantPids[pid] = api.Envoy
		}
	}

	if linkerdPids, err := discoverRelevantLinkerdPids(procfs, pods); err != nil {
		log.Warn().Msg(fmt.Sprintf("Unable to discover linkerd pids - %v", err))
	} else {
		for _, pid := range linkerdPids {
			relevantPids[pid] = api.Linkerd
		}
	}

	return relevantPids
}

func buildBPFExpr(pods []v1.Pod) string {
	hostsFilter := make([]string, 0)

	for _, pod := range pods {
		hostsFilter = append(hostsFilter, fmt.Sprintf("host %s", pod.Status.PodIP))
	}

	return fmt.Sprintf("%s and port not 443", strings.Join(hostsFilter, " or "))
}

func (m *PacketSourceManager) setBPFFilter(pods []v1.Pod) {
	if len(pods) == 0 {
		log.Print("No pods provided, skipping pcap bpf filter")
		return
	}

	var expr string

	if len(pods) > bpfFilterMaxPods {
		log.Info().Msg(fmt.Sprintf("Too many pods for setting ebpf filter %d, setting just not 443", len(pods)))
		expr = "port not 443"
	} else {
		expr = buildBPFExpr(pods)
	}

	log.Info().Msg(fmt.Sprintf("Setting pcap bpf filter %s", expr))

	for pid, src := range m.sources {
		if err := src.setBPFFilter(expr); err != nil {
			log.Info().Msg(fmt.Sprintf("Error setting bpf filter for %s %v - %v", pid, src, err))
		}
	}
}

func (m *PacketSourceManager) Close() {
	for _, src := range m.sources {
		src.close()
	}
}

func (m *PacketSourceManager) Stats() string {
	result := ""

	for _, source := range m.sources {
		packetsReceived, packetsDropped, err := source.Stats()

		if err != nil {
			result = result + fmt.Sprintf("[%s: err:%s]", source.String(), err)
		} else {
			result = result + fmt.Sprintf("[%s: rec: %d dropped: %d]", source.String(), packetsReceived, packetsDropped)
		}
	}

	return result
}
