package models

import (
	"encoding/json"

	"github.com/kubeshark/worker/api"
	v1 "k8s.io/api/core/v1"

	basenine "github.com/up9inc/basenine/client/go"
)

type WebSocketMessageType string

const (
	WebSocketMessageTypeEntry            WebSocketMessageType = "entry"
	WebSocketMessageTypeFullEntry        WebSocketMessageType = "fullEntry"
	WebSocketMessageTypeTappedEntry      WebSocketMessageType = "tappedEntry"
	WebSocketMessageTypeUpdateStatus     WebSocketMessageType = "status"
	WebSocketMessageTypeUpdateTappedPods WebSocketMessageType = "tappedPods"
	WebSocketMessageTypeToast            WebSocketMessageType = "toast"
	WebSocketMessageTypeQueryMetadata    WebSocketMessageType = "queryMetadata"
	WebSocketMessageTypeStartTime        WebSocketMessageType = "startTime"
	WebSocketMessageTypeTapConfig        WebSocketMessageType = "tapConfig"
)

type WebSocketMessageMetadata struct {
	MessageType WebSocketMessageType `json:"messageType,omitempty"`
}

type WebSocketStatusMessage struct {
	*WebSocketMessageMetadata
	TappingStatus []TappedPodStatus `json:"tappingStatus"`
}

type WebSocketTappedPodsMessage struct {
	*WebSocketMessageMetadata
	NodeToTappedPodMap NodeToPodsMap `json:"nodeToTappedPodMap"`
}

type WebSocketTapConfigMessage struct {
	*WebSocketMessageMetadata
	TapTargets []v1.Pod `json:"pods"`
}

type WebSocketEntryMessage struct {
	*WebSocketMessageMetadata
	Data *api.BaseEntry `json:"data,omitempty"`
}

type WebSocketFullEntryMessage struct {
	*WebSocketMessageMetadata
	Data *api.Entry `json:"data,omitempty"`
}

type WebSocketTappedEntryMessage struct {
	*WebSocketMessageMetadata
	Data *api.OutputChannelItem
}

type WebSocketToastMessage struct {
	*WebSocketMessageMetadata
	Data *ToastMessage `json:"data,omitempty"`
}

type WebSocketQueryMetadataMessage struct {
	*WebSocketMessageMetadata
	Data *basenine.Metadata `json:"data,omitempty"`
}

type WebSocketStartTimeMessage struct {
	*WebSocketMessageMetadata
	Data int64 `json:"data"`
}

func CreateBaseEntryWebSocketMessage(base *api.BaseEntry) ([]byte, error) {
	message := &WebSocketEntryMessage{
		WebSocketMessageMetadata: &WebSocketMessageMetadata{
			MessageType: WebSocketMessageTypeEntry,
		},
		Data: base,
	}
	return json.Marshal(message)
}

func CreateFullEntryWebSocketMessage(entry *api.Entry) ([]byte, error) {
	message := &WebSocketFullEntryMessage{
		WebSocketMessageMetadata: &WebSocketMessageMetadata{
			MessageType: WebSocketMessageTypeFullEntry,
		},
		Data: entry,
	}
	return json.Marshal(message)
}

func CreateWebsocketTappedEntryMessage(base *api.OutputChannelItem) ([]byte, error) {
	message := &WebSocketTappedEntryMessage{
		WebSocketMessageMetadata: &WebSocketMessageMetadata{
			MessageType: WebSocketMessageTypeTappedEntry,
		},
		Data: base,
	}
	return json.Marshal(message)
}

func CreateWebsocketToastMessage(base *ToastMessage) ([]byte, error) {
	message := &WebSocketToastMessage{
		WebSocketMessageMetadata: &WebSocketMessageMetadata{
			MessageType: WebSocketMessageTypeToast,
		},
		Data: base,
	}
	return json.Marshal(message)
}

func CreateWebsocketQueryMetadataMessage(base *basenine.Metadata) ([]byte, error) {
	message := &WebSocketQueryMetadataMessage{
		WebSocketMessageMetadata: &WebSocketMessageMetadata{
			MessageType: WebSocketMessageTypeQueryMetadata,
		},
		Data: base,
	}
	return json.Marshal(message)
}

func CreateWebsocketStartTimeMessage(base int64) ([]byte, error) {
	message := &WebSocketStartTimeMessage{
		WebSocketMessageMetadata: &WebSocketMessageMetadata{
			MessageType: WebSocketMessageTypeStartTime,
		},
		Data: base,
	}
	return json.Marshal(message)
}