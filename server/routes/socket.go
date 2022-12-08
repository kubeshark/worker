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
	"github.com/kubeshark/worker/assemblers"
	"github.com/kubeshark/worker/kubernetes/resolver"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/protos"
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

	pcapFiles, err := os.ReadDir("./data")
	if err != nil {
		log.Error().Err(err).Msg("Failed get the list of PCAP files!")
	}

	outputChannel := make(chan *api.OutputChannelItem)
	go writeChannelToSocket(outputChannel, ws)

	go func() {
		for _, pcap := range pcapFiles {
			handlePcapFile(pcap.Name(), outputChannel, opts)
		}
	}()

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
				if event.Op&fsnotify.Remove == fsnotify.Remove {
					_, filename := filepath.Split(event.Name)
					handlePcapFile(filename, outputChannel, opts)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Fatal().Err(err).Msg("Watcher error:")
			}
		}

	}()

	err = watcher.Add("./data")
	if err != nil {
		log.Fatal().Err(err).Msg("Add failed:")
	}
	<-done
}

func handlePcapFile(filename string, outputChannel chan *api.OutputChannelItem, opts *misc.Opts) {
	if strings.HasSuffix(filename, "tmp") {
		return
	}

	log.Info().Str("pcap", filename).Msg("Reading:")
	streamsMap := assemblers.NewTcpStreamMap(false)
	packets := make(chan source.TcpPacketInfo)
	s, err := source.NewTcpPacketSource(filename, "data/"+filename, "", "libpcap", api.Pcap)
	if err != nil {
		log.Error().Err(err).Str("pcap", filename).Msg("Failed to create TCP packet source!")
		return
	}
	go s.ReadPackets(packets)

	assembler, err := assemblers.NewTcpAssembler(filename, false, outputChannel, streamsMap, opts)
	if err != nil {
		log.Error().Err(err).Str("pcap", filename).Msg("Failed creating TCP assembler:")
		return
	}
	for {
		packetInfo, ok := <-packets
		if !ok {
			break
		}
		assembler.ProcessPacket(packetInfo, false)
	}
}

func writeChannelToSocket(outputChannel <-chan *api.OutputChannelItem, ws *websocket.Conn) {
	for item := range outputChannel {
		log.Info().Interface("item", item).Msg("New item:")

		// TODO: The previously bad design forces us to Marshal and Unmarshal
		data, err := json.Marshal(item)
		if err != nil {
			log.Error().Err(err).Msg("Failed marshalling item:")
			break
		}
		var finalItem *api.OutputChannelItem
		err = json.Unmarshal(data, &finalItem)
		if err != nil {
			log.Error().Err(err).Msg("Failed unmarshalling item:")
			break
		}

		baseEntry := summarizeItem(finalItem)
		baseEntry.Id = item.Id

		summary, err := json.Marshal(baseEntry)
		if err != nil {
			log.Error().Err(err).Msg("Failed marshalling summary:")
			break
		}

		err = ws.WriteMessage(1, summary)
		if err != nil {
			log.Error().Err(err).Msg("Failed to set write message to WebSocket:")
			break
		}
	}
}

func itemToEntry(item *api.OutputChannelItem) *api.Entry {
	extension := protos.ExtensionsMap[item.Protocol.Name]

	resolvedSource, resolvedDestination, namespace := resolveIP(item.ConnectionInfo)

	if namespace == "" && item.Namespace != api.UnknownNamespace {
		namespace = item.Namespace
	}

	return extension.Dissector.Analyze(item, resolvedSource, resolvedDestination, namespace)
}

func summarizeItem(item *api.OutputChannelItem) *api.BaseEntry {
	extension := protos.ExtensionsMap[item.Protocol.Name]

	return extension.Dissector.Summarize(itemToEntry(item))
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
