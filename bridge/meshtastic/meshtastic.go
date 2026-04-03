package bmeshtastic

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/42wim/matterbridge/bridge"
	"github.com/42wim/matterbridge/bridge/config"
	meshtastic "github.com/exepirit/meshtastic-go/pkg/meshtastic"
	http "github.com/exepirit/meshtastic-go/pkg/meshtastic/http"
	meshtastic_proto "github.com/exepirit/meshtastic-go/pkg/meshtastic/proto"
	udp "github.com/exepirit/meshtastic-go/pkg/meshtastic/udp"
	lru "github.com/hashicorp/golang-lru"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

type Bmeshtastic struct {
	deviceTx *meshtastic.Device
	state    *meshtastic.DeviceState
	primary  *meshtastic_proto.Channel

	transportRx meshtastic.MeshTransport
	idSeen      *expirable.LRU[uint32, struct{}]
	nodeName    *lru.Cache

	*bridge.Config
}

func init() {
	// TODO: should be in main
	udp.Logger = slog.Default()
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
	transportTx := &http.Transport{
		URL: "http://" + b.GetString("Host"),
		// TODO: disable keep-alive to minimize ESP32 heap consumption
	}

	b.Log.Infof("Connecting %s", transportTx.URL)
	deviceTx := &meshtastic.Device{
		Transport: transportTx,
	}
	state, err := deviceTx.Config().GetState(context.Background())
	if err != nil {
		return err
	}
	if state.MyInfo == nil {
		return fmt.Errorf("initial config did not provide MyInfo (another client running?)")
	}
	deviceTx.NodeID = state.MyInfo.MyNodeNum
	b.Log.Infof("MyInfo: %+v", state.MyInfo)
	b.Log.Infof("Metadata: %+v", state.Device)
	b.Log.Infof("Channels: %+v", redactPskChannels(state.Channels))
	b.Log.Infof("Network config: %+v", state.NetworkConfig)
	b.deviceTx = deviceTx
	b.state = &state

	if state.NetworkConfig.EnabledProtocols&uint32(meshtastic_proto.Config_NetworkConfig_UDP_BROADCAST) == 0 {
		return fmt.Errorf("device must have UDP broadcast enabled (https://meshtastic.org/docs/configuration/radio/network/#protocol-flags)")
	}

	transportRx, err := udp.NewTransport(b.GetString("Host"))
	if err != nil {
		return err
	}
	b.transportRx = transportRx

	b.idSeen = expirable.NewLRU[uint32, struct{}](1000, nil, 1*time.Minute)
	b.nodeName, err = lru.New(1000)
	if err != nil {
		return err
	}

	for _, node := range state.Nodes {
		if node.User != nil {
			b.nodeName.Add(node.Num, node.User.ShortName)
		}
	}
	b.Log.Infof("Added %d nodes to name cache", b.nodeName.Len())

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

	go b.receive()

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
		Id:      rand.Uint32(), // TODO: meshtastic-go, and firmware, assigns
		To:      meshtastic.BroadcastNodenum,
		Channel: uint32(b.primary.Index),
		PayloadVariant: &meshtastic_proto.MeshPacket_Decoded{
			Decoded: &meshtastic_proto.Data{
				Portnum:      meshtastic_proto.PortNum_TEXT_MESSAGE_APP,
				Payload:      []byte(text),
				WantResponse: true, // TODO: no
			}},
		Priority: meshtastic_proto.MeshPacket_RELIABLE,
		WantAck:  true,
	}
	b.idSeen.Add(packet.Id, struct{}{})
	b.Log.Debugf("Sending packet %v", packet)

	err := b.deviceTx.SendToMesh(context.Background(), packet)

	return "", err
}

func (b *Bmeshtastic) decrypt(packet *meshtastic_proto.MeshPacket) (*meshtastic_proto.Data, error) {
	// https://github.com/meshtastic/firmware/blob/53f189fff4b05b171d6f2500e17d6d14da1e6403/src/mesh/Router.cpp#L302

	// https://github.com/meshtastic/meshtastic/blob/master/docs/about/overview/encryption/index.mdx
	// https://github.com/meshtastic/firmware/blob/53f189fff4b05b171d6f2500e17d6d14da1e6403/src/mesh/Channels.cpp#L206
	var psk []byte
	switch len(b.primary.Settings.Psk) {
	case 0:
		return nil, fmt.Errorf("encryption is disabled")
	case 1:
		switch b.primary.Settings.Psk[0] {
		case 0:
			return nil, fmt.Errorf("encryption is disabled")
		default:
			psk = []byte{0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
				0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01}
			psk[len(psk)-1] += b.primary.Settings.Psk[0] - 1
		}
	default:
		psk = b.primary.Settings.Psk
	}

	if len(psk) != aes.BlockSize {
		panic("wrong psk size")
	}

	block, err := aes.NewCipher(psk)
	if err != nil {
		panic(err)
	}

	// https://github.com/meshtastic/firmware/blob/master/src/mesh/CryptoEngine.cpp#L243
	packetId := uint64(packet.Id)
	extraNonce := uint32(0)
	nonce := &bytes.Buffer{}
	if err := binary.Write(nonce, binary.LittleEndian, &packetId); err != nil {
		panic(err)
	}
	if err := binary.Write(nonce, binary.LittleEndian, &packet.From); err != nil {
		panic(err)
	}
	if err := binary.Write(nonce, binary.LittleEndian, &extraNonce); err != nil {
		panic(err)
	}
	if nonce.Len() != 16 {
		panic("wrong nonce length")
	}

	stream := cipher.NewCTR(block, nonce.Bytes())

	payload := packet.GetEncrypted()

	stream.XORKeyStream(payload, payload)

	data := &meshtastic_proto.Data{}
	if err := proto.Unmarshal(payload, data); err != nil {
		return nil, err
	}

	return data, nil
}

func (b *Bmeshtastic) receive() {
	for {
		packet, err := b.transportRx.ReceiveFromMesh(context.Background())
		if err != nil {
			var level logrus.Level
			if errors.Is(err, meshtastic.ErrInvalidPacketFormat) {
				// Individual packet couldn't be decoded - continue receiving
				level = logrus.WarnLevel
			} else {
				// TODO: handle this more gracefully? connect loop?
				level = logrus.FatalLevel
			}

			b.Log.Log(level, "Receive error: %v", err)

			if level == logrus.WarnLevel {
				continue
			} else {
				break
			}
		}

		// TODO: support DMs

		const PrimaryChannelHash = 8

		if packet.To == meshtastic.BroadcastNodenum && packet.Channel == PrimaryChannelHash {
			var data *meshtastic_proto.Data
			if packet.GetDecoded() != nil {
				data = packet.GetDecoded()
			} else if packet.GetEncrypted() != nil {
				data, err = b.decrypt(packet)
				if err != nil {
					b.Log.Infof("Decrypt error: %v", err)
					continue
				}
			} else {
				b.Log.Errorf("Unexpected payload variant: %v", packet)
			}

			switch data.Portnum {
			case meshtastic_proto.PortNum_NODEINFO_APP:
				user := new(meshtastic_proto.User)
				err = proto.Unmarshal(data.Payload, user)
				if err != nil {
					b.Log.Warnf("Failed to parse NodeInfo payload: %v (%+v)", err, data)
					break
				}
				b.Log.Debugf("User: %+v", user)
				b.nodeName.Add(packet.From, user.ShortName)
			case meshtastic_proto.PortNum_TEXT_MESSAGE_APP:
				if !b.idSeen.Contains(packet.Id) {
					b.idSeen.Add(packet.Id, struct{}{})

					nameIntf, found := b.nodeName.Get(packet.From)
					var name string
					if found {
						name = nameIntf.(string)
					} else {
						name = fmt.Sprintf("%04x", packet.From&0xffff)
					}

					b.Remote <- config.Message{
						Username: name, Text: string(data.Payload),
						Channel: "PRIMARY", Account: b.Account,
					}
				}
			}
		}
	}
}
