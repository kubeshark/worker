package tracer

import (
	"bufio"
	"io"
	"time"

	"github.com/kubeshark/base/pkg/api"
	"github.com/rs/zerolog/log"
)

type seqNumbers struct {
	Seq uint32
	Ack uint32
}

type tlsReader struct {
	chunks        chan *tracerTlsChunk
	seenChunks    int
	data          []byte
	progress      *api.ReadProgress
	tcpID         *api.TcpID
	isClient      bool
	captureTime   time.Time
	extension     *api.Extension
	emitter       api.Emitter
	counterPair   *api.CounterPair
	parent        *tlsStream
	reqResMatcher api.RequestResponseMatcher
	seqNumbers    *seqNumbers
}

func NewTlsReader(tcpID *api.TcpID, parent *tlsStream, isClient bool,
	emitter api.Emitter, extension *api.Extension, reqResMatcher api.RequestResponseMatcher) *tlsReader {
	return &tlsReader{
		chunks:        make(chan *tracerTlsChunk, 1),
		progress:      &api.ReadProgress{},
		tcpID:         tcpID,
		isClient:      isClient,
		captureTime:   time.Now(),
		extension:     extension,
		emitter:       emitter,
		counterPair:   &api.CounterPair{},
		parent:        parent,
		reqResMatcher: reqResMatcher,
		seqNumbers:    &seqNumbers{},
	}
}

func (r *tlsReader) run(options *api.TrafficFilteringOptions) {
	b := bufio.NewReader(r)

	err := r.extension.Dissector.Dissect(b, r, options)

	if err != nil {
		log.Warn().Err(err).Interface("tcp-id", r.GetTcpID()).Msg("While dissecting TLS")
	}
}

func (r *tlsReader) newChunk(chunk *tracerTlsChunk) {
	r.captureTime = time.Now()
	r.seenChunks = r.seenChunks + 1

	r.parent.writeData(chunk.getRecordedData(), r)

	r.chunks <- chunk
}

func (r *tlsReader) close() {
	close(r.chunks)
	r.parent.close()
}

func (r *tlsReader) Read(p []byte) (int, error) {
	var chunk *tracerTlsChunk

	for len(r.data) == 0 {
		var ok bool
		select {
		case chunk, ok = <-r.chunks:
			if !ok {
				return 0, io.EOF
			}

			r.data = chunk.getRecordedData()
		case <-time.After(time.Second * 120):
			r.close()
			return 0, io.EOF
		}

		if len(r.data) > 0 {
			break
		}
	}

	l := copy(p, r.data)
	r.data = r.data[l:]
	r.progress.Feed(l)

	return l, nil
}

func (r *tlsReader) GetReqResMatcher() api.RequestResponseMatcher {
	return r.reqResMatcher
}

func (r *tlsReader) GetIsClient() bool {
	return r.isClient
}

func (r *tlsReader) GetReadProgress() *api.ReadProgress {
	return r.progress
}

func (r *tlsReader) GetParent() api.TcpStream {
	return r.parent
}

func (r *tlsReader) GetTcpID() *api.TcpID {
	return r.tcpID
}

func (r *tlsReader) GetCounterPair() *api.CounterPair {
	return r.counterPair
}

func (r *tlsReader) GetCaptureTime() time.Time {
	return r.captureTime
}

func (r *tlsReader) GetEmitter() api.Emitter {
	return r.emitter
}

func (r *tlsReader) GetIsClosed() bool {
	return false
}
