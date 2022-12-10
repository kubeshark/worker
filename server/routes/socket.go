package routes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/base/pkg/extensions"
	"github.com/kubeshark/base/pkg/languages/kfl"
	"github.com/kubeshark/worker/assemblers"
	"github.com/kubeshark/worker/kubernetes/resolver"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/source"
	"github.com/rs/zerolog/log"
)

var (
	websocketUpgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
)

func init() {
	websocketUpgrader.CheckOrigin = func(r *http.Request) bool { return true } // like cors for web socket
}

func WebSocketRoutes(app *gin.Engine, opts *misc.Opts) {
	app.GET("/ws", func(c *gin.Context) {
		websocketHandler(c, opts)
	})
}

func websocketHandler(c *gin.Context, opts *misc.Opts) {
	ws, err := websocketUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to set WebSocket upgrade:")
		return
	}
	defer ws.Close()

	pcapFiles, err := os.ReadDir(misc.GetDataDir())
	if err != nil {
		log.Error().Err(err).Msg("Failed get the list of PCAP files!")
	}

	quit := make(chan bool)
	outputChannel := make(chan *api.OutputChannelItem)
	go writeChannelToSocket(outputChannel, ws, c.Query("q"), quit)

	for _, pcap := range pcapFiles {
		handlePcapFile(pcap.Name(), outputChannel, opts)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal().Err(err).Msg("NewWatcher failed:")
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		defer close(done)

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Rename == fsnotify.Rename || event.Op&fsnotify.Create == fsnotify.Create {
					_, filename := filepath.Split(event.Name)
					handlePcapFile(filename, outputChannel, opts)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Fatal().Err(err).Msg("Watcher error:")
			case <-quit:
				return
			}
		}

	}()

	err = watcher.Add(misc.GetDataDir())
	if err != nil {
		log.Fatal().Err(err).Msg("Add failed:")
	}
	<-done
}

func handlePcapFile(id string, outputChannel chan *api.OutputChannelItem, opts *misc.Opts) {
	if strings.HasSuffix(id, "tmp") {
		return
	}

	log.Debug().Str("pcap", id).Msg("Reading:")
	streamsMap := assemblers.NewTcpStreamMap(false)
	packets := make(chan source.TcpPacketInfo)
	pcapPath := misc.GetPcapPath(id)
	s, err := source.NewTcpPacketSource(id, misc.GetPcapPath(id), "", "libpcap", api.Pcap)
	if err != nil {
		log.Error().Err(err).Str("pcap", id).Msg("Failed to create TCP packet source!")
		return
	}
	go s.ReadPackets(packets)

	if _, ok := misc.AlivePcaps.Load(pcapPath); ok {
		go processPackets(id, outputChannel, opts, streamsMap, packets, s)
	} else {
		processPackets(id, outputChannel, opts, streamsMap, packets, s)
	}
}

func processPackets(id string, outputChannel chan *api.OutputChannelItem, opts *misc.Opts,
	streamsMap api.TcpStreamMap, packets chan source.TcpPacketInfo, s *source.TcpPacketSource) {
	assembler := assemblers.NewTcpAssembler(id, false, outputChannel, streamsMap, opts)
	for {
		packetInfo, ok := <-packets
		if !ok {
			break
		}
		assembler.ProcessPacket(packetInfo, false)
	}

	s.Handle.Close()
}

func writeChannelToSocket(outputChannel <-chan *api.OutputChannelItem, ws *websocket.Conn, query string, quit chan bool) {
	for item := range outputChannel {
		// TODO: The previously bad design forces us to Marshal and Unmarshal
		data, err := json.Marshal(item)
		if err != nil {
			log.Error().Err(err).Msg("Failed marshalling item:")
			continue
		}
		var finalItem *api.OutputChannelItem
		err = json.Unmarshal(data, &finalItem)
		if err != nil {
			log.Error().Err(err).Msg("Failed unmarshalling item:")
			continue
		}

		entry := itemToEntry(finalItem)
		entryMarshaled, err := json.Marshal(entry)
		if err != nil {
			log.Error().Err(err).Msg("Failed marshalling entry:")
			continue
		}

		truth, record, err := kfl.Apply(entryMarshaled, query)
		if err != nil {
			log.Error().Err(err).Msg("Failed applying query:")
			continue
		}

		if !truth {
			continue
		}

		var alteredEntry *api.Entry
		err = json.Unmarshal([]byte(record), &alteredEntry)
		if err != nil {
			log.Error().Err(err).Msg("Failed unmarshalling altered item:")
			continue
		}

		baseEntry := summarizeEntry(alteredEntry)
		baseEntry.Id = item.Id

		summary, err := json.Marshal(baseEntry)
		if err != nil {
			log.Error().Err(err).Msg("Failed marshalling summary:")
			continue
		}

		err = ws.WriteMessage(1, summary)
		if err != nil {
			log.Error().Err(err).Msg("Failed to set write message to WebSocket:")
			quit <- true
			return
		}
	}
}

func itemToEntry(item *api.OutputChannelItem) *api.Entry {
	extension := extensions.ExtensionsMap[item.Protocol.Name]

	resolvedSource, resolvedDestination, namespace := resolveIP(item.ConnectionInfo)

	if namespace == "" && item.Namespace != api.UnknownNamespace {
		namespace = item.Namespace
	}

	return extension.Dissector.Analyze(item, resolvedSource, resolvedDestination, namespace)
}

func summarizeEntry(entry *api.Entry) *api.BaseEntry {
	extension := extensions.ExtensionsMap[entry.Protocol.Name]

	return extension.Dissector.Summarize(entry)
}

func resolveIP(connectionInfo *api.ConnectionInfo) (resolvedSource string, resolvedDestination string, namespace string) {
	if resolver.K8sResolver != nil {
		unresolvedSource := connectionInfo.ClientIP
		resolvedSourceObject := resolver.K8sResolver.Resolve(unresolvedSource)
		if resolvedSourceObject == nil {
			log.Debug().Str("source", unresolvedSource).Msg("Cannot find resolved name!")
			if os.Getenv("SKIP_NOT_RESOLVED_SOURCE") == "1" {
				return
			}
		} else {
			resolvedSource = resolvedSourceObject.FullAddress
			namespace = resolvedSourceObject.Namespace
		}

		unresolvedDestination := fmt.Sprintf("%s:%s", connectionInfo.ServerIP, connectionInfo.ServerPort)
		resolvedDestinationObject := resolver.K8sResolver.Resolve(unresolvedDestination)
		if resolvedDestinationObject == nil {
			log.Debug().Str("destination", unresolvedDestination).Msg("Cannot find resolved name!")
			if os.Getenv("SKIP_NOT_RESOLVED_DEST") == "1" {
				return
			}
		} else {
			resolvedDestination = resolvedDestinationObject.FullAddress
			// Overwrite namespace (if it was set according to the source)
			// Only overwrite if non-empty
			if resolvedDestinationObject.Namespace != "" {
				namespace = resolvedDestinationObject.Namespace
			}
		}
	}
	return resolvedSource, resolvedDestination, namespace
}
