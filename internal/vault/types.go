package vault

import "encoding/json"

// Secret owns a mutable copy of secret text so the decrypted vault can erase
// it deterministically. Converting a Secret to a string for a third-party API
// creates a short-lived immutable Go value that the runtime controls.
type Secret []byte

func NewSecret(value string) Secret { return append(Secret(nil), value...) }

func (secret Secret) String() string { return string(secret) }

func (secret Secret) MarshalJSON() ([]byte, error) { return json.Marshal(string(secret)) }

func (secret *Secret) UnmarshalJSON(input []byte) error {
	var value string
	if err := json.Unmarshal(input, &value); err != nil {
		return err
	}
	secret.Destroy()
	*secret = append(Secret(nil), value...)
	return nil
}

func (secret Secret) Destroy() {
	for index := range secret {
		secret[index] = 0
	}
}

type Credentials map[string]Secret

type Integrations map[string]Credentials

func (credentials Credentials) Set(name string, value Secret) {
	if previous, exists := credentials[name]; exists {
		previous.Destroy()
	}
	credentials[name] = value
}

func (credentials Credentials) Strings() map[string]string {
	values := make(map[string]string, len(credentials))
	for name, value := range credentials {
		values[name] = value.String()
	}
	return values
}

func (credentials Credentials) Destroy() {
	for name, value := range credentials {
		value.Destroy()
		delete(credentials, name)
	}
}

type Data struct {
	ControlPlane ControlPlane `json:"control_plane"`
	Integrations Integrations `json:"integrations,omitempty"`
}

type ControlPlane struct {
	URL               string `json:"url"`
	BeaconID          string `json:"beacon_id"`
	BeaconName        string `json:"beacon_name"`
	SigningPrivateKey Secret `json:"signing_private_key"`
	SigningPublicKey  string `json:"signing_public_key"`
}

func (controlPlane *ControlPlane) SetSigningPrivateKey(value Secret) {
	controlPlane.SigningPrivateKey.Destroy()
	controlPlane.SigningPrivateKey = value
}

func Empty() Data {
	return Data{Integrations: make(Integrations)}
}

func (data *Data) Destroy() {
	data.ControlPlane.SigningPrivateKey.Destroy()
	data.ControlPlane.SigningPrivateKey = nil
	for name, credentials := range data.Integrations {
		credentials.Destroy()
		delete(data.Integrations, name)
	}
}

func (integrations Integrations) Strings() map[string]map[string]string {
	values := make(map[string]map[string]string, len(integrations))
	for name, credentials := range integrations {
		values[name] = credentials.Strings()
	}
	return values
}
