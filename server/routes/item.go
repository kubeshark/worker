package routes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/base/pkg/extensions"
	"github.com/kubeshark/base/pkg/languages/kfl"
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
	_id := c.Param("id")
	idIndex := strings.Split(_id, "-")
	if len(idIndex) < 2 {
		msg := "Malformed ID!"
		log.Error().Str("id", _id).Msg(msg)
		handleError(c, fmt.Errorf(msg))
		return
	}
	id := idIndex[0]
	index, err := strconv.ParseInt(idIndex[1], 0, 10)
	if err != nil {
		log.Error().Err(err).Str("pcap", id).Str("index", idIndex[1]).Msg("Failed parsing index!")
		handleError(c, err)
		return
	}

	query := c.Query("q")

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

	assembler := assemblers.NewTcpAssembler(id, false, outputChannel, streamsMap, opts)
	go func() {
		for {
			packetInfo, ok := <-packets
			if !ok {
				break
			}
			assembler.ProcessPacket(packetInfo, false)
		}
	}()

	var i int64 = -1
	for item := range outputChannel {
		i++
		if i < index {
			continue
		}

		// TODO: The previously bad design forces us to Marshal and Unmarshal
		var data []byte
		data, err = json.Marshal(item)
		if err != nil {
			log.Error().Err(err).Msg("Failed marshalling item:")
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

		protocol := extensions.ProtocolsMap[entry.Protocol.ToString()]
		extension := extensions.ExtensionsMap[entry.Protocol.Name]

		var entryMarshaled []byte
		entryMarshaled, err = json.Marshal(entry)
		if err != nil {
			log.Error().Err(err).Msg("Failed marshalling entry:")
			break
		}

		var truth bool
		var record string
		truth, record, err = kfl.Apply(entryMarshaled, query)
		if err != nil {
			log.Error().Err(err).Msg("Failed applying query:")
			break
		}

		if !truth {
			c.JSON(http.StatusBadRequest, gin.H{
				"query":   query,
				"message": "Query evaluates to false for this item.",
			})
			return
		}

		var alteredEntry *api.Entry
		err = json.Unmarshal([]byte(record), &alteredEntry)
		if err != nil {
			log.Error().Err(err).Msg("Failed unmarshalling altered entry:")
			break
		}

		base := extension.Dissector.Summarize(alteredEntry)
		var representation []byte
		representation, err = extension.Dissector.Represent(alteredEntry.Request, alteredEntry.Response)
		if err != nil {
			log.Error().Err(err).Msg("Failed representing altered entry:")
			break
		}

		entryWrapped := &api.EntryWrapper{
			Protocol:       *protocol,
			Representation: string(representation),
			Data:           entry,
			Base:           base,
		}

		c.JSON(http.StatusOK, entryWrapped)
		return
	}

	handleError(c, err)
}
