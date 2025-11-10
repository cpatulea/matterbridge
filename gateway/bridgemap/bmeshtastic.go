//go:build !nomeshtastic
// +build !nomeshtastic

package bridgemap

import bmeshtastic "github.com/42wim/matterbridge/bridge/meshtastic"

func init() {
	FullMap["meshtastic"] = bmeshtastic.New
}
