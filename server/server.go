package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kubeshark/base/pkg/api"
	"github.com/kubeshark/worker/assemblers"
	"github.com/kubeshark/worker/server/middlewares"
	"github.com/kubeshark/worker/server/routes"
	"github.com/rs/zerolog/log"
)

func Build(opts *assemblers.Opts, streamsMap api.TcpStreamMap) *gin.Engine {
	ginApp := gin.Default()

	ginApp.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "It's running.")
	})

	ginApp.Use(middlewares.CORSMiddleware())

	routes.WebSocketRoutes(ginApp, opts, streamsMap)

	return ginApp
}

func Start(app *gin.Engine, port int) {
	signals := make(chan os.Signal, 2)
	signal.Notify(signals,
		os.Interrupt,    // this catch ctrl + c
		syscall.SIGTSTP, // this catch ctrl + z
	)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: app,
	}

	go func() {
		<-signals
		log.Warn().Msg("Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := srv.Shutdown(ctx)
		if err != nil {
			log.Error().Err(err).Send()
		}
		os.Exit(0)
	}()

	// Run server.
	log.Info().Int("port", port).Msg("Starting the server...")
	if err := app.Run(fmt.Sprintf(":%d", port)); err != nil {
		log.Error().Err(err).Msg("Server is not running!")
	}
}
