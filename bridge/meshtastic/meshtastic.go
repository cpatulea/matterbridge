package bmeshtastic

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/42wim/matterbridge/bridge"
	"github.com/42wim/matterbridge/bridge/config"
	meshtastic "github.com/exepirit/meshtastic-go/pkg/meshtastic"
	http "github.com/exepirit/meshtastic-go/pkg/meshtastic/http"
	meshtastic_proto "github.com/exepirit/meshtastic-go/pkg/meshtastic/proto"
	"google.golang.org/protobuf/proto"
)

type Bmeshtastic struct {
	device  *meshtastic.Device
	state   *meshtastic.DeviceState
	primary *meshtastic_proto.Channel

	*bridge.Config
}

func init() {
	// TODO: should be in main
	slog.SetLogLoggerLevel(slog.LevelDebug)
}

func New(cfg *bridge.Config) bridge.Bridger {
	b := &Bmeshtastic{}
	b.Config = cfg
	return b
}

func redactPsk(channel *meshtastic_proto.Channel) *meshtastic_proto.Channel {
	ch := proto.Clone(channel).(*meshtastic_proto.Channel)

	safe := false
	switch len(ch.Settings.Psk) {
	case 0:
		safe = true
	case 1:
		if ch.Settings.Psk[0] == 0 || ch.Settings.Psk[0] == 1 {
			safe = true
		}
	}

	if !safe {
		ch.Settings.Psk = []byte(fmt.Sprintf("<redacted %d bytes>", len(ch.Settings.Psk)))
	}
	return ch
}

func redactPskChannels(channels []*meshtastic_proto.Channel) []*meshtastic_proto.Channel {
	out := []*meshtastic_proto.Channel{}
	for _, ch := range channels {
		out = append(out, redactPsk(ch))
	}
	return out
}

func (b *Bmeshtastic) Connect() error {
	transport := &http.Transport{
		URL: "http://" + b.GetString("Host"),
	}

	b.Log.Infof("Connecting %s", transport.URL)
	device := &meshtastic.Device{
		Transport: transport,
	}
	state, err := device.Config().GetState(context.Background())
	if err != nil {
		return err
	}
	if state.MyInfo == nil {
		return fmt.Errorf("initial config did not provide MyInfo (another client running?)")
	}
	device.NodeID = state.MyInfo.MyNodeNum
	b.Log.Infof("MyInfo: %+v", state.MyInfo)
	b.Log.Infof("Metadata: %+v", state.Device)
	b.Log.Infof("Channels: %+v", redactPskChannels(state.Channels))
	b.device = device
	b.state = &state
	return nil
}

func (b *Bmeshtastic) JoinChannel(channel config.ChannelInfo) error {
	if channel.Name != "PRIMARY" {
		return fmt.Errorf("only PRIMARY channel is supported")
	}

	var primary *meshtastic_proto.Channel
	for _, ch := range b.state.Channels {
		if ch.Role == meshtastic_proto.Channel_PRIMARY {
			primary = ch
			break
		}
	}
	if primary == nil {
		return fmt.Errorf("PRIMARY channel not found")
	}
	b.Log.Infof("PRIMARY channel: %+v", redactPsk(primary))
	b.primary = primary

	return nil
}

func (b *Bmeshtastic) Send(msg config.Message) (string, error) {
	// ignore delete messages
	if msg.Event == config.EventMsgDelete {
		return "", nil
	}

	b.Log.Debugf("=> Receiving %#v", msg)

	text := msg.Username + msg.Text
	if len(text) > 200 {
		text = text[:len(text)-len(" <clipped message>")] + " <clipped message>"
	}

	packet := &meshtastic_proto.MeshPacket{
		To:      meshtastic.BroadcastNodenum,
		Channel: uint32(b.primary.Index),
		PayloadVariant: &meshtastic_proto.MeshPacket_Decoded{
			Decoded: &meshtastic_proto.Data{
				Portnum:      meshtastic_proto.PortNum_TEXT_MESSAGE_APP,
				Payload:      []byte(text),
				WantResponse: true,
			}},
		Priority: meshtastic_proto.MeshPacket_RELIABLE,
		WantAck:  true,
	}
	b.Log.Debugf("Sending packet %v", packet)

	err := b.device.SendToMesh(context.Background(), packet)

	return "", err
}
