package assemblers

import (
	"time"

	"github.com/google/gopacket"
	"github.com/kubeshark/base/pkg/api"
)

type tcpReaderDataMsg struct {
	bytes []byte
	ci    gopacket.CaptureInfo
}

func NewTcpReaderDataMsg(data []byte, ci gopacket.CaptureInfo) api.TcpReaderDataMsg {
	length := len(data)
	ci.Length = length
	ci.CaptureLength = length
	return &tcpReaderDataMsg{data, ci}
}

func (dataMsg *tcpReaderDataMsg) GetBytes() []byte {
	return dataMsg.bytes
}

func (dataMsg *tcpReaderDataMsg) GetTimestamp() time.Time {
	return dataMsg.ci.Timestamp
}

func (dataMsg *tcpReaderDataMsg) GetCaptureInfo() gopacket.CaptureInfo {
	return dataMsg.ci
}
