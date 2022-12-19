package controllers

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kubeshark/worker/kubernetes/resolver"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/misc/mergecap"
	"github.com/kubeshark/worker/misc/replay"
	"github.com/rs/zerolog/log"
)

func GetTotalTcpStreams(c *gin.Context) {
	pcapsDir := misc.GetPcapsDir()
	pcapFiles, err := os.ReadDir(pcapsDir)
	if err != nil {
		log.Error().Err(err).Msg("Failed get the list of PCAP files!")
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	var counter int64
	for _, pcap := range pcapFiles {
		if filepath.Ext(pcap.Name()) != ".pcap" {
			continue
		}

		counter++
	}

	c.JSON(http.StatusOK, gin.H{
		"total": counter,
	})
}

func GetMerge(c *gin.Context) {
	pcapsDir := misc.GetPcapsDir()
	pcapFiles, err := os.ReadDir(pcapsDir)
	if err != nil {
		log.Error().Err(err).Msg("Failed get the list of PCAP files!")
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	outFile, err := os.CreateTemp(pcapsDir, "mergecap")
	if err != nil {
		log.Error().Err(err).Msg("Failed to create the out file for PCAP merger!")
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	defer outFile.Close()
	defer os.Remove(outFile.Name())

	err = mergecap.Mergecap(pcapFiles, outFile)
	if err != nil {
		log.Error().Err(err).Msg("Failed to merge the PCAP files!")
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	attachmentName := fmt.Sprintf("%d.pcap", time.Now().Unix())

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Content-Disposition", "attachment; filename="+attachmentName)
	c.Header("Content-Type", "application/octet-stream")
	c.File(outFile.Name())
}

func GetReplay(c *gin.Context) {
	id := c.Param("id")

	pcapPath := misc.GetPcapPath(id)
	err := replay.Replay(pcapPath, replay.DefaultRouteInterface(""))
	if err != nil {
		log.Error().Str("path", pcapPath).Err(err).Msg("Couldn't replay the PCAP:")
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": http.StatusOK,
	})
}

func GetNameResolutionHistory(c *gin.Context) {
	res := resolver.K8sResolver
	m := res.GetDumpNameResolutionHistoryMap()
	c.JSON(http.StatusOK, m)
}
