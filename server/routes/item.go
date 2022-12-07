package routes

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/worker/assemblers"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/source"
	"github.com/rs/zerolog/log"
)

func ItemRoutes(ginApp *gin.Engine, opts *misc.Opts) {
	routeGroup := ginApp.Group("/item")

	routeGroup.GET("/:id", func(c *gin.Context) {
		getItem(c, opts)
	})
}

func handleError(c *gin.Context, err error) {
	_ = c.Error(err)
	c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
		"msg": err.Error(),
	})
}

func getItem(c *gin.Context, opts *misc.Opts) {
	id := c.Param("id")

	outputChannel := make(chan *api.OutputChannelItem)

	streamsMap := assemblers.NewTcpStreamMap(false)
	packets := make(chan source.TcpPacketInfo)
	s, err := source.NewTcpPacketSource(id, "data/"+id, "", "libpcap", api.Pcap)
	if err != nil {
		log.Error().Err(err).Str("pcap", id).Msg("Failed to create TCP packet source!")
		handleError(c, err)
		return
	}
	go s.ReadPackets(packets)

	assembler, err := assemblers.NewTcpAssembler(id, false, outputChannel, streamsMap, opts)
	if err != nil {
		log.Error().Err(err).Str("pcap", id).Msg("Failed creating TCP assembler:")
		handleError(c, err)
		return
	}
	go func() {
		for {
			packetInfo, ok := <-packets
			if !ok {
				break
			}
			assembler.ProcessPacket(packetInfo, false)
		}
	}()

	for item := range outputChannel {
		// TODO: The previously bad design forces us to Marshal and Unmarshal
		data, err := json.Marshal(item)
		if err != nil {
			log.Error().Err(err).Msg("Failed marshalling item:")
			handleError(c, err)
			break
		}
		var finalItem *api.OutputChannelItem
		err = json.Unmarshal(data, &finalItem)
		if err != nil {
			log.Error().Err(err).Msg("Failed unmarshalling item:")
			handleError(c, err)
			break
		}

		entry := itemToEntry(finalItem)
		entry.Id = id

		c.JSON(http.StatusOK, entry)
		break
	}
}
