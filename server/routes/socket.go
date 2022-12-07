package routes

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/worker/assemblers"
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

	pcapFiles, err := os.ReadDir("./data")
	if err != nil {
		log.Error().Err(err).Msg("Failed get the list of PCAP files!")
	}

	streamsMap := assemblers.NewTcpStreamMap(false)

	outputChannel := make(chan *api.OutputChannelItem)
	go writeChannelToSocket(outputChannel, ws)

	for _, pcap := range pcapFiles {
		log.Info().Str("pcap", pcap.Name()).Msg("Reading:")
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

		data, err := json.Marshal(item)
		if err != nil {
			log.Error().Err(err).Msg("Failed marshalling item:")
			break
		}

		err = ws.WriteMessage(1, data)
		if err != nil {
			log.Error().Err(err).Msg("Failed to set write message to WebSocket:")
			break
		}
	}
}
