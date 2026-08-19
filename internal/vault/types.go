package vault

type Data struct {
	ControlPlane ControlPlane                 `json:"control_plane"`
	Integrations map[string]map[string]string `json:"integrations,omitempty"`
}

type ControlPlane struct {
	URL               string `json:"url"`
	BeaconID          string `json:"beacon_id"`
	BeaconName        string `json:"beacon_name"`
	SigningPrivateKey string `json:"signing_private_key"`
	SigningPublicKey  string `json:"signing_public_key"`
}

func Empty() Data {
	return Data{Integrations: make(map[string]map[string]string)}
}
