package misc

import (
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
)

var dataDir = "data"

func InitDataDir() {
	body, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		log.Error().Err(err).Msg("Unable to get the machine ID:")
	}
	machineId := strings.TrimSpace(string(body))
	log.Info().Str("id", machineId).Msg("Machine ID is:")
	newDataDir := fmt.Sprintf("%s/%s", dataDir, machineId)
	err = os.MkdirAll(newDataDir, os.ModePerm)
	if err != nil {
		log.Error().Err(err).Str("data-dir", newDataDir).Msg("Unable to create the new data directory:")
	} else {
		dataDir = newDataDir
		log.Info().Str("data-dir", dataDir).Msg("Set the data directory to:")
	}
}

func GetDataDir() string {
	return fmt.Sprintf("./%s", dataDir)
}

func GetPcapPath(id string) string {
	return fmt.Sprintf("%s/%s", GetDataDir(), id)
}

func BuildPcapPath(id int64) string {
	return fmt.Sprintf("%s/tcp_stream_%09d.pcap", GetDataDir(), id)
}

func BuildTmpPcapPath(id int64) string {
	return fmt.Sprintf("%stmp", BuildPcapPath(id))
}
