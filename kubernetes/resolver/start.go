package resolver

import (
	"context"

	"github.com/rs/zerolog/log"
)

var K8sResolver *Resolver

func StartResolving(namespace string) {
	errOut := make(chan error, 100)
	res, err := NewFromInCluster(errOut, namespace)
	if err != nil {
		log.Error().Err(err).Msg("While creating K8s resolver!")
		return
	}
	ctx := context.Background()
	res.Start(ctx)
	go func() {
		for {
			err := <-errOut
			log.Error().Err(err).Msg("Name resolution failed:")
		}
	}()

	K8sResolver = res
}
