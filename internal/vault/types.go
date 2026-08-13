package vault

type Data struct {
	ControlPlane ControlPlane                 `json:"control_plane"`
	Integrations map[string]map[string]string `json:"integrations,omitempty"`
}

type ControlPlane struct {
	URL         string `json:"url"`
	BeaconID    string `json:"beacon_id"`
	BeaconToken string `json:"beacon_token"`
}

func Empty() Data {
	return Data{Integrations: make(map[string]map[string]string)}
}
