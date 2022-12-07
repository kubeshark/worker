package tracer

import "github.com/kubeshark/base/pkg/api"

type tlsStream struct {
	id           string
	identifyMode bool
	emittable    bool
	reader       *tlsReader
	protocol     *api.Protocol
}

func (t *tlsStream) GetOrigin() api.Capture {
	return api.Ebpf
}

func (t *tlsStream) SetProtocol(protocol *api.Protocol) {
	t.protocol = protocol
}

func (t *tlsStream) SetAsEmittable() {
	t.emittable = true
}

func (t *tlsStream) GetId() string {
	return t.id
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
