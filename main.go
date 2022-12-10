package main

import (
	"flag"
	"os"
	"os/signal"
	"time"

	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/base/pkg/extensions"
	"github.com/kubeshark/worker/assemblers"
	"github.com/kubeshark/worker/kubernetes/resolver"
	"github.com/kubeshark/worker/misc"
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

	misc.InitDataDir()
	misc.InitAlivePcapsMap()

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
	startWorker(opts, streamsMap, filteredOutputItemsChannel, extensions.Extensions, filteringOptions)

	ginApp := server.Build(opts)
	server.Start(ginApp, *port)
}

func getTrafficFilteringOptions() *api.TrafficFilteringOptions {
	return &api.TrafficFilteringOptions{
		IgnoredUserAgents: []string{},
	}
}
