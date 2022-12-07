package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/base/pkg/models"
	"github.com/kubeshark/worker/assemblers"
	"github.com/kubeshark/worker/kubernetes/resolver"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/protos"
	"github.com/kubeshark/worker/server"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var statsevery = flag.Int("stats", 60, "Output statistics every N seconds")
var verbose = flag.Bool("verbose", false, "Be verbose")
var port = flag.Int("port", 80, "Port number of the HTTP server")
var debug = flag.Bool("debug", false, "Enable debug mode")
var quiet = flag.Bool("quiet", false, "Be quiet regarding errors")
var procfs = flag.String("procfs", "/proc", "The procfs directory, used when mapping host volumes into a container")
var ignoredPorts = flag.String("ignore-ports", "", "A comma separated list of ports to ignore")
var maxLiveStreams = flag.Int("max-live-streams", 500, "Maximum live streams to handle concurrently")

// capture
var iface = flag.String("i", "en0", "Interface to read packets from")
var staleTimeoutSeconds = flag.Int("staletimout", 120, "Max time in seconds to keep connections which don't transmit data")
var servicemesh = flag.Bool("servicemesh", false, "Record decrypted traffic if the cluster is configured with a service mesh and with mtls")
var tls = flag.Bool("tls", false, "Enable TLS tracing")
var packetCapture = flag.String("packet-capture", "libpcap", "Packet capture backend. Possible values: libpcap, af_packet")

var memprofile = flag.String("memprofile", "", "Write memory profile")

const (
	HostModeEnvVar             = "HOST_MODE"
	NodeNameEnvVar             = "NODE_NAME"
	socketConnectionRetries    = 30
	socketConnectionRetryDelay = time.Second * 2
	socketHandshakeTimeout     = time.Second * 2
)

func main() {
	flag.Parse()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	protos.LoadExtensions()

	run()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	<-signalChan

	log.Info().Msg("Exiting")
}

func run() {
	log.Info().Msg("Starting worker...")

	resolver.StartResolving("")

	hostMode := os.Getenv(HostModeEnvVar) == "1"
	opts := &misc.Opts{
		HostMode: hostMode,
	}
	streamsMap := assemblers.NewTcpStreamMap(true)

	filteredOutputItemsChannel := make(chan *api.OutputChannelItem)

	filteringOptions := getTrafficFilteringOptions()
	startWorker(opts, streamsMap, filteredOutputItemsChannel, protos.Extensions, filteringOptions)

	ginApp := server.Build(opts)
	server.Start(ginApp, *port)
}

func getTrafficFilteringOptions() *api.TrafficFilteringOptions {
	return &api.TrafficFilteringOptions{
		IgnoredUserAgents: []string{},
	}
}

func dialSocketWithRetry(socketAddress string, retryAmount int, retryDelay time.Duration) (*websocket.Conn, error) {
	var lastErr error
	dialer := &websocket.Dialer{ // we use our own dialer instead of the default due to the default's 45 sec handshake timeout, we occasionally encounter hanging socket handshakes when Worker tries to connect to Hub too soon
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: socketHandshakeTimeout,
	}
	for i := 1; i < retryAmount; i++ {
		socketConnection, _, err := dialer.Dial(socketAddress, nil)
		if err != nil {
			lastErr = err
			if i < retryAmount {
				log.Warn().Err(err).Str("addr", socketAddress).Msg(fmt.Sprintf("Socket connection attempt is failed! Retrying %d out of %d in %d seconds...", i, retryAmount, retryDelay/time.Second))
				time.Sleep(retryDelay)
			}
		} else {
			go handleIncomingMessageAsWorker(socketConnection)
			return socketConnection, nil
		}
	}
	return nil, lastErr
}

func handleIncomingMessageAsWorker(socketConnection *websocket.Conn) {
	for {
		if _, message, err := socketConnection.ReadMessage(); err != nil {
			log.Error().Err(err).Msg("While reading message from the socket connection!")
			if errors.Is(err, syscall.EPIPE) {
				// socket has disconnected, we can safely stop this goroutine
				return
			}
		} else {
			var socketMessageBase models.WebSocketMessageMetadata
			if err := json.Unmarshal(message, &socketMessageBase); err != nil {
				log.Error().Err(err).Msg("Couldn't unmarshal socket message!")
			} else {
				switch socketMessageBase.MessageType {
				case models.WebSocketMessageTypeWorkerConfig:
					var configMessage *models.WebSocketWorkerConfigMessage
					if err := json.Unmarshal(message, &configMessage); err != nil {
						log.Error().Err(err).Str("msg", string(message)).Msg("Received unknown message from the socket connection:")
					} else {
						UpdateTargets(configMessage.TargettedPods)
					}
				case models.WebSocketMessageTypeUpdateTargettedPods:
					var targettedPodsMessage models.WebSocketTargettedPodsMessage
					if err := json.Unmarshal(message, &targettedPodsMessage); err != nil {
						log.Error().Err(err).Str("msg-type", string(socketMessageBase.MessageType)).Msg("Couldn't unmarshal message of message type:")
						return
					}
					nodeName := os.Getenv(NodeNameEnvVar)
					UpdateTargets(targettedPodsMessage.NodeToTargettedPodsMap[nodeName])
				default:
					log.Error().Str("msg-type", string(socketMessageBase.MessageType)).Msg("Received a socket message type which no handlers are defined for!")
				}
			}
		}
	}
}
