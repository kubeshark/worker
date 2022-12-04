package routes

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/kubeshark/base/pkg/api"
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

func WebSocketRoutes(app *gin.Engine) {
	app.GET("/ws", func(c *gin.Context) {
		websocketHandler(c)
	})
}

func websocketHandler(c *gin.Context) {
	ws, err := websocketUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to set WebSocket upgrade:")
		return
	}

	pcapFiles, err := os.ReadDir("./data")
	if err != nil {
		log.Error().Err(err).Msg("Failed get the list of PCAP files!")
	}

	// outputChannel := make(chan *api.OutputChannelItem)
	packets := make(chan source.TcpPacketInfo)

	for _, pcap := range pcapFiles {
		s, err := source.NewTcpPacketSource("ws", pcap.Name(), "", "libpcap", api.Pcap)
		log.Error().Err(err).Msg("Failed to create TCP packet source!")
		go s.ReadPackets(packets)

		// assembler := NewTcpAssembler(false, outputChannel, streamsMap, opts)
		// assembler.processPackets(packets)
	}

	for {
		err = ws.WriteMessage(1, []byte("Hi Client!"))
		if err != nil {
			log.Error().Err(err).Msg("Failed to set write message to WebSocket:")
			break
		}
	}
}
