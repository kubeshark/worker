package assemblers

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	_debug "runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/worker/diagnose"
	"github.com/kubeshark/worker/misc"
	"github.com/rs/zerolog/log"
)

type tcpStreamMap struct {
	streams  *sync.Map
	streamId int64
}

func getIdFromPcapFiles() int64 {
	pcapFiles, err := os.ReadDir(misc.GetDataDir())
	if err != nil {
		log.Error().Err(err).Msg("Failed get the list of PCAP files!")
		return 0
	}

	if len(pcapFiles) == 0 {
		var id int64 = 0
		log.Info().Int("id", int(id)).Msg("No PCAP files are found! Starting from zero:")
		return id
	}

	filename := pcapFiles[len(pcapFiles)-1].Name()
	segments := strings.Split(filename[:len(filename)-len(filepath.Ext(filename))], "_")
	segment := strings.TrimLeft(segments[len(segments)-1], "0")

	id, err := strconv.ParseInt(segment, 0, 10)
	if err != nil {
		log.Error().Err(err).Str("segment", segment).Msg("Can't parse the segment:")
		return 0
	}

	log.Info().Int("id", int(id)).Msg("Continuing from stream ID:")

	return id
}

func NewTcpStreamMap(cont bool) api.TcpStreamMap {
	var streamId int64
	if cont {
		streamId = getIdFromPcapFiles()
	}
	return &tcpStreamMap{
		streams:  &sync.Map{},
		streamId: streamId,
	}
}

func (streamMap *tcpStreamMap) Range(f func(key, value interface{}) bool) {
	streamMap.streams.Range(f)
}

func (streamMap *tcpStreamMap) Store(key, value interface{}) {
	streamMap.streams.Store(key, value)
	diagnose.AppStats.IncLiveTcpStreams()
}

func (streamMap *tcpStreamMap) Delete(key interface{}) {
	streamMap.streams.Delete(key)
	diagnose.AppStats.DecLiveTcpStreams()
}

func (streamMap *tcpStreamMap) NextId() int64 {
	streamMap.streamId++
	return streamMap.streamId
}

func (streamMap *tcpStreamMap) CloseTimedoutTcpStreamChannels() {
	tcpStreamChannelTimeoutMs := GetTcpChannelTimeoutMs()
	closeTimedoutTcpChannelsIntervalMs := GetCloseTimedoutTcpChannelsInterval()
	log.Info().
		Msg(fmt.Sprintf(
			"Using %d ms as the close timedout TCP stream channels interval",
			closeTimedoutTcpChannelsIntervalMs/time.Millisecond,
		))

	ticker := time.NewTicker(closeTimedoutTcpChannelsIntervalMs)
	for {
		<-ticker.C

		_debug.FreeOSMemory()
		streamMap.streams.Range(func(key interface{}, value interface{}) bool {
			// `*tlsStream` is not yet applicable to this routine.
			// So, we cast into `(*tcpStream)` and ignore `*tlsStream`
			stream, ok := value.(*tcpStream)
			if !ok {
				return true
			}

			if stream.protocol == nil {
				if !stream.isClosed && time.Now().After(stream.createdAt.Add(tcpStreamChannelTimeoutMs)) {
					stream.close()
					diagnose.AppStats.IncDroppedTcpStreams()
					log.Debug().
						Msg(fmt.Sprintf(
							"Dropped an unidentified TCP stream because of timeout. Total dropped: %d Total Goroutines: %d Timeout (ms): %d",
							diagnose.AppStats.DroppedTcpStreams,
							runtime.NumGoroutine(),
							tcpStreamChannelTimeoutMs/time.Millisecond,
						))
				}
			}
			return true
		})
	}
}
