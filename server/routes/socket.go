package routes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

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

	for _, pcap := range pcapFiles {
		if strings.HasSuffix(pcap.Name(), "tmp") {
			continue
		}

		log.Info().Str("pcap", pcap.Name()).Msg("Reading:")
		streamsMap := assemblers.NewTcpStreamMap(false)
		packets := make(chan source.TcpPacketInfo)
		s, err := source.NewTcpPacketSource(pcap.Name(), "data/"+pcap.Name(), "", "libpcap", api.Pcap)
		if err != nil {
			log.Error().Err(err).Str("pcap", pcap.Name()).Msg("Failed to create TCP packet source!")
			continue
		}
		go s.ReadPackets(packets)

		assembler, err := assemblers.NewTcpAssembler(false, outputChannel, streamsMap, opts)
		if err != nil {
			log.Error().Err(err).Str("pcap", pcap.Name()).Msg("Failed creating TCP assembler:")
			continue
		}
		for {
			packetInfo, ok := <-packets
			if !ok {
				break
			}
			assembler.ProcessPacket(packetInfo, false)
		}
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

		summary, err := json.Marshal(summarizeItem(finalItem))
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
