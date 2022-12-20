package tracer

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/go-errors/errors"
	"github.com/hashicorp/golang-lru/simplelru"
	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/ebpf/perf"
	"github.com/kubeshark/worker/diagnose"
	"github.com/rs/zerolog/log"
)

const (
	fdCachedItemAvgSize = 40
	fdCacheMaxItems     = 500000 / fdCachedItemAvgSize
)

type tlsPoller struct {
	tls            *Tracer
	streams        map[string]*tlsStream
	readers        map[string]*tlsReader
	closedReaders  chan string
	reqResMatcher  api.RequestResponseMatcher
	chunksReader   *perf.Reader
	extension      *api.Extension
	procfs         string
	pidToNamespace sync.Map
	fdCache        *simplelru.LRU // Actual type is map[string]addressPair
	evictedCounter int
}

func newTlsPoller(tls *Tracer, extension *api.Extension, procfs string) (*tlsPoller, error) {
	poller := &tlsPoller{
		tls:           tls,
		streams:       make(map[string]*tlsStream),
		readers:       make(map[string]*tlsReader),
		closedReaders: make(chan string, 100),
		reqResMatcher: extension.Dissector.NewResponseRequestMatcher(),
		extension:     extension,
		chunksReader:  nil,
		procfs:        procfs,
	}

	fdCache, err := simplelru.NewLRU(fdCacheMaxItems, poller.fdCacheEvictCallback)

	if err != nil {
		return nil, errors.Wrap(err, 0)
	}

	poller.fdCache = fdCache
	return poller, nil
}

func (p *tlsPoller) init(bpfObjects *tracerObjects, bufferSize int) error {
	var err error

	p.chunksReader, err = perf.NewReader(bpfObjects.ChunksBuffer, bufferSize)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	return nil
}

func (p *tlsPoller) close() error {
	return p.chunksReader.Close()
}

func (p *tlsPoller) poll(outputItems chan *api.OutputChannelItem, options *api.TrafficFilteringOptions, streamsMap api.TcpStreamMap) {
	// tracerTlsChunk is generated by bpf2go.
	chunks := make(chan *tracerTlsChunk)

	go p.pollChunksPerfBuffer(chunks)

	for {
		select {
		case chunk, ok := <-chunks:
			if !ok {
				return
			}

			if err := p.handleTlsChunk(chunk, p.extension, outputItems, options, streamsMap); err != nil {
				LogError(err)
			}
		case key := <-p.closedReaders:
			delete(p.readers, key)
		}
	}
}

func (p *tlsPoller) pollChunksPerfBuffer(chunks chan<- *tracerTlsChunk) {
	log.Info().Msg("Start polling for tls events")

	for {
		record, err := p.chunksReader.Read()

		if err != nil {
			close(chunks)

			if errors.Is(err, perf.ErrClosed) {
				return
			}

			LogError(errors.Errorf("Error reading chunks from tls perf, aborting TLS! %v", err))
			return
		}

		if record.LostSamples != 0 {
			log.Info().Msg(fmt.Sprintf("Buffer is full, dropped %d chunks", record.LostSamples))
			continue
		}

		buffer := bytes.NewReader(record.RawSample)

		var chunk tracerTlsChunk

		if err := binary.Read(buffer, binary.LittleEndian, &chunk); err != nil {
			LogError(errors.Errorf("Error parsing chunk %v", err))
			continue
		}

		chunks <- &chunk
	}
}

func (p *tlsPoller) handleTlsChunk(chunk *tracerTlsChunk, extension *api.Extension, outputItems chan *api.OutputChannelItem,
	options *api.TrafficFilteringOptions, streamsMap api.TcpStreamMap) error {
	address := chunk.getAddressPair()

	// Creates one *tlsStream per TCP stream
	streamKey := buildTlsStreamKey(address, chunk.isRequest())
	stream, streamExists := p.streams[streamKey]
	if !streamExists {
		stream = NewTlsStream(streamsMap)
		stream.setId(streamsMap.NextId())
		streamsMap.Store(stream.getId(), stream)
		p.streams[streamKey] = stream
	}

	// Creates two *tlsReader (s) per TCP stream
	key := buildTlsKey(address)
	reader, exists := p.readers[key]
	if !exists {
		reader = p.startNewTlsReader(chunk, &address, key, outputItems, extension, options, stream)
		p.readers[key] = reader
	}

	reader.newChunk(chunk)

	return nil
}

func (p *tlsPoller) startNewTlsReader(chunk *tracerTlsChunk, address *addressPair, key string,
	outputItems chan *api.OutputChannelItem, extension *api.Extension, options *api.TrafficFilteringOptions,
	stream *tlsStream) *tlsReader {

	tcpid := p.buildTcpId(address)

	doneHandler := func(r *tlsReader) {
		p.closeReader(key, r)
		stream.close()
	}

	var emitter api.Emitter = &api.Emitting{
		AppStats:      &diagnose.AppStats,
		Stream:        stream,
		OutputChannel: outputItems,
	}

	tlsEmitter := &tlsEmitter{
		delegate:  emitter,
		namespace: p.getNamespace(chunk.Pid),
	}

	reader := &tlsReader{
		key:           key,
		chunks:        make(chan *tracerTlsChunk, 1),
		doneHandler:   doneHandler,
		progress:      &api.ReadProgress{},
		tcpID:         &tcpid,
		isClient:      chunk.isRequest(),
		captureTime:   time.Now(),
		extension:     extension,
		emitter:       tlsEmitter,
		counterPair:   &api.CounterPair{},
		parent:        stream,
		reqResMatcher: p.reqResMatcher,
	}
	stream.reader = reader

	go dissect(extension, reader, options)
	return reader
}

func dissect(extension *api.Extension, reader api.TcpReader, options *api.TrafficFilteringOptions) {
	b := bufio.NewReader(reader)

	err := extension.Dissector.Dissect(b, reader, options)

	if err != nil {
		log.Warn().Err(err).Interface("tcp-id", reader.GetTcpID()).Msg("While dissecting TLS")
	}
}

func (p *tlsPoller) closeReader(key string, r *tlsReader) {
	close(r.chunks)
	p.closedReaders <- key
}

func buildTlsKey(address addressPair) string {
	return fmt.Sprintf("%s:%d>%s:%d", address.srcIp, address.srcPort, address.dstIp, address.dstPort)
}

func buildTlsStreamKey(address addressPair, isRequest bool) string {
	if isRequest {
		return fmt.Sprintf("%s:%d>%s:%d", address.srcIp, address.srcPort, address.dstIp, address.dstPort)
	} else {
		return fmt.Sprintf("%s:%d>%s:%d", address.dstIp, address.dstPort, address.srcIp, address.srcPort)
	}
}

func (p *tlsPoller) buildTcpId(address *addressPair) api.TcpID {
	return api.TcpID{
		SrcIP:   address.srcIp.String(),
		DstIP:   address.dstIp.String(),
		SrcPort: strconv.FormatUint(uint64(address.srcPort), 10),
		DstPort: strconv.FormatUint(uint64(address.dstPort), 10),
		Ident:   "",
	}
}

func (p *tlsPoller) addPid(pid uint32, namespace string) {
	p.pidToNamespace.Store(pid, namespace)
}

func (p *tlsPoller) getNamespace(pid uint32) string {
	namespaceIfc, ok := p.pidToNamespace.Load(pid)

	if !ok {
		return api.UnknownNamespace
	}

	namespace, ok := namespaceIfc.(string)

	if !ok {
		return api.UnknownNamespace
	}

	return namespace
}

func (p *tlsPoller) clearPids() {
	p.pidToNamespace.Range(func(key, v interface{}) bool {
		p.pidToNamespace.Delete(key)
		return true
	})
}

func (p *tlsPoller) fdCacheEvictCallback(key interface{}, value interface{}) {
	p.evictedCounter = p.evictedCounter + 1

	if p.evictedCounter%1000000 == 0 {
		log.Info().Msg(fmt.Sprintf("Tls fdCache evicted %d items", p.evictedCounter))
	}
}
