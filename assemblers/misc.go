package assemblers

import (
	"time"

	"github.com/kubeshark/base/pkg/api"
	v1 "k8s.io/api/core/v1"
)

type Opts struct {
	HostMode               bool
	IgnoredPorts           []uint16
	MaxLiveStreams         int
	StaleConnectionTimeout time.Duration
}

var FilteringOptions *api.TrafficFilteringOptions // global
var TargettedPods []v1.Pod                        // global
