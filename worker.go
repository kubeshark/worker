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
	"github.com/kubeshark/worker/assemblers"
	"github.com/kubeshark/worker/diagnose"
	"github.com/kubeshark/worker/misc"
	"github.com/kubeshark/worker/source"
	"github.com/kubeshark/worker/target"
	"github.com/kubeshark/worker/tracer"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/cpu"
	"github.com/struCoder/pidusage"
)

const cleanPeriod = time.Second * 10

func startWorker(opts *misc.Opts, streamsMap api.TcpStreamMap, outputItems chan *api.OutputChannelItem, extensions []*api.Extension, options *api.TrafficFilteringOptions) {
	misc.FilteringOptions = options

	if *tls {
		for _, e := range extensions {
			if e.Protocol.Name == "http" {
				target.TracerInstance = startTracer(e, outputItems, options, streamsMap)
				break
			}
		}
	}

	if assemblers.GetMemoryProfilingEnabled() {
		diagnose.StartMemoryProfiler(
			os.Getenv(assemblers.MemoryProfilingDumpPath),
			os.Getenv(assemblers.MemoryProfilingTimeIntervalSeconds))
	}

	assembler := initializeWorker(opts, outputItems, streamsMap)
	go startAssembler(streamsMap, assembler)
}

func printPeriodicStats(cleaner *Cleaner, assembler *assemblers.TcpAssembler) {
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
				assemblerStats.FlushedConnections,
				assemblerStats.ClosedConnections,
				cleanStats.deleted,
			))
		currentAppStats := diagnose.AppStats.DumpStats()
		appStatsJSON, _ := json.Marshal(currentAppStats)
		log.Info().Msg(fmt.Sprintf("App stats - %v", string(appStatsJSON)))

		// At the moment
		log.Info().Msg(fmt.Sprintf("assembler-stats: %s, packet-source-stats: %s", assembler.Dump(), target.PacketSourceManager.Stats()))
	}
}

func initializePacketSources() error {
	if target.PacketSourceManager != nil {
		target.PacketSourceManager.Close()
	}

	var err error
	target.PacketSourceManager, err = source.NewPacketSourceManager(*procfs, *iface, *servicemesh, misc.TargettedPods, *packetCapture, target.MainPacketInputChan)
	return err
}

func initializeWorker(opts *misc.Opts, outputItems chan *api.OutputChannelItem, streamsMap api.TcpStreamMap) *assemblers.TcpAssembler {
	diagnose.InitializeErrorsMap(*debug, *verbose, *quiet)
	diagnose.InitializeWorkerInternalStats()

	target.MainPacketInputChan = make(chan source.TcpPacketInfo)

	if err := initializePacketSources(); err != nil {
		log.Fatal().Err(err).Send()
	}

	opts.IgnoredPorts = append(opts.IgnoredPorts, buildIgnoredPortsList(*ignoredPorts)...)
	opts.StaleConnectionTimeout = time.Duration(*staleTimeoutSeconds) * time.Second

	return assemblers.NewTcpAssembler("", true, outputItems, streamsMap, opts)
}

func startAssembler(streamsMap api.TcpStreamMap, assembler *assemblers.TcpAssembler) {
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

	assembler.ProcessPackets(target.MainPacketInputChan)

	if diagnose.ErrorsMap.OutputLevel >= 2 {
		assembler.DumpStreamPool()
	}

	if err := diagnose.DumpMemoryProfile(*memprofile); err != nil {
		log.Error().Err(err).Msg("Couldn't dump memory profile!")
	}

	assembler.WaitAndDump()

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

	if err := tracer.UpdateTargets(&tls, &misc.TargettedPods, *procfs); err != nil {
		tracer.LogError(err)
		return nil
	}

	// A quick way to instrument libssl.so without PID filtering - used for debuging and troubleshooting
	//
	if os.Getenv("KUBESHARK_GLOBAL_LIBSSL_PID") != "" {
		if err := tls.GlobalSSLLibTarget(*procfs, os.Getenv("KUBESHARK_GLOBAL_LIBSSL_PID")); err != nil {
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

	go tls.PollForLogging()
	go tls.Poll(outputItems, options, streamsMap)

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
