package tracer

import "github.com/kubeshark/base/pkg/api"

type tlsStream struct {
	reader   *tlsReader
	protocol *api.Protocol
}

func (t *tlsStream) GetOrigin() api.Capture {
	return api.Ebpf
}

func (t *tlsStream) SetProtocol(protocol *api.Protocol) {
	t.protocol = protocol
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
