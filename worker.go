package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/worker/diagnose"
	"github.com/kubeshark/worker/source"
	"github.com/kubeshark/worker/tracer"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/cpu"
	"github.com/struCoder/pidusage"
	v1 "k8s.io/api/core/v1"
)

const cleanPeriod = time.Second * 10

type Opts struct {
	HostMode               bool
	IgnoredPorts           []uint16
	maxLiveStreams         int
	staleConnectionTimeout time.Duration
}

var extensions []*api.Extension                     // global
var filteringOptions *api.TrafficFilteringOptions   // global
var targettedPods []v1.Pod                          // global
var packetSourceManager *source.PacketSourceManager // global
var mainPacketInputChan chan source.TcpPacketInfo   // global
var tracerInstance *tracer.Tracer                   // global

func startWorker(opts *Opts, outputItems chan *api.OutputChannelItem, extensionsRef []*api.Extension, options *api.TrafficFilteringOptions) {
	extensions = extensionsRef
	filteringOptions = options

	streamsMap := NewTcpStreamMap()

	if *tls {
		for _, e := range extensions {
			if e.Protocol.Name == "http" {
				tracerInstance = startTracer(e, outputItems, options, streamsMap)
				break
			}
		}
	}

	if GetMemoryProfilingEnabled() {
		diagnose.StartMemoryProfiler(os.Getenv(MemoryProfilingDumpPath), os.Getenv(MemoryProfilingTimeIntervalSeconds))
	}

	assembler, err := initializeWorker(opts, outputItems, streamsMap)

	if err != nil {
		log.Error().Err(err).Msg("Coudln't initialize the worker!")
		return
	}

	go startAssembler(streamsMap, assembler)
}

func UpdateTargets(newTargets []v1.Pod) {
	success := true

	targettedPods = newTargets

	packetSourceManager.UpdatePods(newTargets, mainPacketInputChan)

	if tracerInstance != nil && os.Getenv("KUBESHARK_GLOBAL_GOLANG_PID") == "" {
		if err := tracer.UpdateTargets(tracerInstance, &newTargets, *procfs); err != nil {
			tracer.LogError(err)
			success = false
		}
	}

	printNewTargets(success)
}

func printNewTargets(success bool) {
	printStr := ""
	for _, pod := range targettedPods {
		printStr += fmt.Sprintf("%s (%s), ", pod.Status.PodIP, pod.Name)
	}
	printStr = strings.TrimRight(printStr, ", ")

	if success {
		log.Info().Msg(fmt.Sprintf("Now targetting: %s", printStr))
	} else {
		log.Error().Msg(fmt.Sprintf("Failed to start targetting: %s", printStr))
	}
}

func printPeriodicStats(cleaner *Cleaner, assembler *tcpAssembler) {
	statsPeriod := time.Second * time.Duration(*statsevery)
	ticker := time.NewTicker(statsPeriod)

	logicalCoreCount, err := cpu.Counts(true)
	if err != nil {
		logicalCoreCount = -1
	}

	physicalCoreCount, err := cpu.Counts(false)
	if err != nil {
		physicalCoreCount = -1
	}

	for {
		<-ticker.C

		// Since the start
		errorMapLen, errorsSummery := diagnose.ErrorsMap.GetErrorsSummary()

		log.Info().
			Msg(fmt.Sprintf(
				"%v (errors: %v, errTypes:%v) - Errors Summary: %s",
				time.Since(diagnose.AppStats.StartTime),
				diagnose.ErrorsMap.ErrorsCount,
				errorMapLen,
				errorsSummery,
			))

		// At this moment
		memStats := runtime.MemStats{}
		runtime.ReadMemStats(&memStats)
		sysInfo, err := pidusage.GetStat(os.Getpid())
		if err != nil {
			sysInfo = &pidusage.SysInfo{
				CPU:    -1,
				Memory: -1,
			}
		}
		log.Info().
			Msg(fmt.Sprintf(
				"heap-alloc: %d, heap-idle: %d, heap-objects: %d, goroutines: %d, cpu: %f, cores: %d/%d, rss: %f",
				memStats.HeapAlloc,
				memStats.HeapIdle,
				memStats.HeapObjects,
				runtime.NumGoroutine(),
				sysInfo.CPU,
				logicalCoreCount,
				physicalCoreCount,
				sysInfo.Memory,
			))

		// Since the last print
		cleanStats := cleaner.dumpStats()
		assemblerStats := assembler.DumpStats()
		log.Info().
			Msg(fmt.Sprintf(
				"Cleaner - flushed connections: %d, closed connections: %d, deleted messages: %d",
				assemblerStats.flushedConnections,
				assemblerStats.closedConnections,
				cleanStats.deleted,
			))
		currentAppStats := diagnose.AppStats.DumpStats()
		appStatsJSON, _ := json.Marshal(currentAppStats)
		log.Info().Msg(fmt.Sprintf("App stats - %v", string(appStatsJSON)))

		// At the moment
		log.Info().Msg(fmt.Sprintf("assembler-stats: %s, packet-source-stats: %s", assembler.Dump(), packetSourceManager.Stats()))
	}
}

func initializePacketSources() error {
	if packetSourceManager != nil {
		packetSourceManager.Close()
	}

	var err error
	packetSourceManager, err = source.NewPacketSourceManager(*procfs, *iface, *servicemesh, targettedPods, *packetCapture, mainPacketInputChan)
	return err
}

func initializeWorker(opts *Opts, outputItems chan *api.OutputChannelItem, streamsMap api.TcpStreamMap) (*tcpAssembler, error) {
	diagnose.InitializeErrorsMap(*debug, *verbose, *quiet)
	diagnose.InitializeWorkerInternalStats()

	mainPacketInputChan = make(chan source.TcpPacketInfo)

	if err := initializePacketSources(); err != nil {
		log.Fatal().Err(err).Send()
	}

	opts.IgnoredPorts = append(opts.IgnoredPorts, buildIgnoredPortsList(*ignoredPorts)...)
	opts.maxLiveStreams = *maxLiveStreams
	opts.staleConnectionTimeout = time.Duration(*staleTimeoutSeconds) * time.Second

	return NewTcpAssembler(true, outputItems, streamsMap, opts)
}

func startAssembler(streamsMap api.TcpStreamMap, assembler *tcpAssembler) {
	go streamsMap.CloseTimedoutTcpStreamChannels()

	diagnose.AppStats.SetStartTime(time.Now())

	staleConnectionTimeout := time.Second * time.Duration(*staleTimeoutSeconds)
	cleaner := Cleaner{
		assembler:         assembler.Assembler,
		cleanPeriod:       cleanPeriod,
		connectionTimeout: staleConnectionTimeout,
		streamsMap:        streamsMap,
	}
	cleaner.start()

	go printPeriodicStats(&cleaner, assembler)

	assembler.processPackets(mainPacketInputChan)

	if diagnose.ErrorsMap.OutputLevel >= 2 {
		assembler.dumpStreamPool()
	}

	if err := diagnose.DumpMemoryProfile(*memprofile); err != nil {
		log.Error().Err(err).Msg("Couldn't dump memory profile!")
	}

	assembler.waitAndDump()

	diagnose.InternalStats.PrintStatsSummary()
	diagnose.ErrorsMap.PrintSummary()
	log.Info().Interface("AppStats", diagnose.AppStats).Send()
}

func startTracer(extension *api.Extension, outputItems chan *api.OutputChannelItem,
	options *api.TrafficFilteringOptions, streamsMap api.TcpStreamMap) *tracer.Tracer {
	tls := tracer.Tracer{}
	chunksBufferSize := os.Getpagesize() * 100
	logBufferSize := os.Getpagesize()

	if err := tls.Init(chunksBufferSize, logBufferSize, *procfs, extension); err != nil {
		tracer.LogError(err)
		return nil
	}

	if err := tracer.UpdateTargets(&tls, &targettedPods, *procfs); err != nil {
		tracer.LogError(err)
		return nil
	}

	// A quick way to instrument libssl.so without PID filtering - used for debuging and troubleshooting
	//
	if os.Getenv("KUBESHARK_GLOBAL_SSL_LIBRARY") != "" {
		if err := tls.GlobalSSLLibTarget(os.Getenv("KUBESHARK_GLOBAL_SSL_LIBRARY")); err != nil {
			tracer.LogError(err)
			return nil
		}
	}

	// A quick way to instrument Go `crypto/tls` without PID filtering - used for debuging and troubleshooting
	//
	if os.Getenv("KUBESHARK_GLOBAL_GOLANG_PID") != "" {
		if err := tls.GlobalGoTarget(*procfs, os.Getenv("KUBESHARK_GLOBAL_GOLANG_PID")); err != nil {
			tracer.LogError(err)
			return nil
		}
	}

	var emitter api.Emitter = &api.Emitting{
		AppStats:      &diagnose.AppStats,
		OutputChannel: outputItems,
	}

	go tls.PollForLogging()
	go tls.Poll(emitter, options, streamsMap)

	return &tls
}

func buildIgnoredPortsList(ignoredPorts string) []uint16 {
	tmp := strings.Split(ignoredPorts, ",")
	result := make([]uint16, len(tmp))

	for i, raw := range tmp {
		v, err := strconv.Atoi(raw)
		if err != nil {
			continue
		}

		result[i] = uint16(v)
	}

	return result
}
