package vaultengine

import (
	"log"
)

// Get list of all engines mounted
func (client *Client) GetMounts() map[string]string {

	secret, err := client.vc.Sys().ListMounts()

	if err != nil {
		log.Fatalf("%v", err)
	}

	mounts := make(map[string]string)
	var EngineType string
	for mount, metadata := range secret {
		if metadata.Type != "generic" && metadata.Type != "kv" {
			continue
		}

		// Generic -> kv1 or if kv depending on version
		if metadata.Type == "generic" {
			EngineType = "kv1"
		} else {
			if metadata.Options["version"] == "1" {
				EngineType = "kv1"
			} else {
				EngineType = "kv2"
			}
		}
		// mount := strings.Replace(mount, "/", "", -1)
		mounts[mount] = EngineType
	}

	if mounts == nil {
		log.Fatalf("No mounts found or your token has no access.")
	}

	return mounts

}
