package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/iamlyio/iamly-beacon/internal/vault"
)

type Action string

const (
	Configure Action = "configure"
	Secrets   Action = "secrets"
	Status    Action = "status"
	Run       Action = "run"
	Quit      Action = "quit"
)

var (
	blue       = lipgloss.Color("#2563EB")
	white      = lipgloss.Color("#F8FAFC")
	muted      = lipgloss.Color("#8491A5")
	panel      = lipgloss.NewStyle().Padding(1, 3).Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#344054"))
	brand      = lipgloss.NewStyle().Bold(true).Foreground(blue)
	title      = lipgloss.NewStyle().Bold(true).Foreground(white)
	mutedStyle = lipgloss.NewStyle().Foreground(muted)
	active     = lipgloss.NewStyle().Bold(true).Foreground(blue)
)

type menuModel struct {
	version string
	cursor  int
	choice  Action
}

var menuItems = []struct {
	name, detail string
	action       Action
}{
	{"Configure", "Connect iamly.io and choose encrypted secret storage", Configure},
	{"Store integration secret", "Enter a vendor credential using masked input", Secrets},
	{"Status", "Inspect the local Beacon without revealing secrets", Status},
	{"Run", "Wait for review collection jobs", Run},
	{"Quit", "Close Beacon", Quit},
}

func Select(version string) (Action, error) {
	result, err := tea.NewProgram(menuModel{version: version}, tea.WithAltScreen()).Run()
	if err != nil {
		return "", err
	}
	return result.(menuModel).choice, nil
}

func (m menuModel) Init() tea.Cmd { return nil }

func (m menuModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyMsg); ok {
		switch key.String() {
		case "ctrl+c", "q", "esc":
			m.choice = Quit
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(menuItems)-1 {
				m.cursor++
			}
		case "enter":
			m.choice = menuItems[m.cursor].action
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m menuModel) View() string {
	view := brand.Render("◆") + "  " + title.Render("Beacon") + "  " + mutedStyle.Render(m.version)
	view += "\n" + mutedStyle.Render("iamly.io collection boundary · credentials stay here") + "\n\n"
	for index, item := range menuItems {
		marker, label := "  ", item.name
		if index == m.cursor {
			marker, label = active.Render("› "), active.Render(label)
		}
		view += fmt.Sprintf("%s%s\n    %s\n\n", marker, label, mutedStyle.Render(item.detail))
	}
	view += mutedStyle.Render("↑/↓ move  •  enter select  •  q quit")
	return panel.Render(view)
}

type SetupResult struct {
	Provider        vault.Provider
	KeyName         string
	Data            vault.Data
	EnrollmentToken string
}

type SecretResult struct {
	Integration string
	Name        string
	Value       string
}

type GuidedSecretResult struct {
	Integration string
	Values      map[string]string
}

type guidedSecretField struct {
	name        string
	label       string
	placeholder string
	secret      bool
}

type guidedSecretSpec struct {
	label  string
	fields []guidedSecretField
}

var guidedSecretSpecs = map[string]guidedSecretSpec{
	"anthropic": {
		label: "Anthropic Console",
		fields: []guidedSecretField{
			{name: "adminApiKey", label: "Admin API key", placeholder: "sk-ant-admin…", secret: true},
		},
	},
	"asana": {
		label: "Asana",
		fields: []guidedSecretField{
			{name: "token", label: "Personal access token", placeholder: "paste token", secret: true},
			{name: "workspaceGid", label: "Workspace ID", placeholder: "1234567890"},
		},
	},
	"bamboohr": {
		label: "BambooHR",
		fields: []guidedSecretField{
			{name: "companyDomain", label: "Company domain", placeholder: "acme"},
			{name: "apiKey", label: "API key", placeholder: "paste API key", secret: true},
		},
	},
	"canva": {
		label: "Canva",
		fields: []guidedSecretField{
			{name: "token", label: "SCIM token", placeholder: "paste SCIM token", secret: true},
		},
	},
	"figma": {
		label: "Figma",
		fields: []guidedSecretField{
			{name: "token", label: "SCIM API token", placeholder: "paste SCIM token", secret: true},
			{name: "tenantId", label: "SCIM tenant ID", placeholder: "1234567890"},
		},
	},
	"gcp": {
		label: "Google Cloud Platform",
		fields: []guidedSecretField{
			{name: "clientEmail", label: "Service-account client email", placeholder: "beacon@project.iam.gserviceaccount.com"},
			{name: "resourceScope", label: "Resource scope", placeholder: "organizations/123456789"},
			{name: "privateKey", label: "Private key (use \\n for line breaks)", placeholder: "-----BEGIN PRIVATE KEY-----\\n…", secret: true}, // gitleaks:allow -- incomplete UI placeholder
		},
	},
	"github": {
		label: "GitHub",
		fields: []guidedSecretField{
			{name: "org", label: "Organization", placeholder: "acme"},
			{name: "token", label: "Access token", placeholder: "paste token", secret: true},
		},
	},
	"google": {
		label: "Google Workspace",
		fields: []guidedSecretField{
			{name: "clientEmail", label: "Service-account client email", placeholder: "beacon@project.iam.gserviceaccount.com"},
			{name: "adminEmail", label: "Delegated administrator email", placeholder: "admin@example.com"},
			{name: "privateKey", label: "Private key (use \\n for line breaks)", placeholder: "-----BEGIN PRIVATE KEY-----\\n…", secret: true},
		},
	},
	"linear": {
		label: "Linear",
		fields: []guidedSecretField{
			{name: "apiKey", label: "Personal API key", placeholder: "lin_api_…", secret: true},
		},
	},
	"notion": {
		label: "Notion",
		fields: []guidedSecretField{
			{name: "token", label: "Internal integration token", placeholder: "ntn_…", secret: true},
		},
	},
	"openai": {
		label: "OpenAI API Platform",
		fields: []guidedSecretField{
			{name: "adminApiKey", label: "Admin API key", placeholder: "sk-admin-…", secret: true},
		},
	},
	"slack": {
		label: "Slack",
		fields: []guidedSecretField{
			{name: "userToken", label: "User OAuth token", placeholder: "xoxp-…", secret: true},
		},
	},
	"tailscale": {
		label: "Tailscale",
		fields: []guidedSecretField{
			{name: "clientId", label: "OAuth client ID", placeholder: "paste client ID"},
			{name: "clientSecret", label: "OAuth client secret", placeholder: "tskey-client-…", secret: true},
		},
	},
	"twingate": {
		label: "Twingate",
		fields: []guidedSecretField{
			{name: "network", label: "Network subdomain", placeholder: "acme"},
			{name: "apiToken", label: "API token", placeholder: "paste API token", secret: true},
		},
	},
	"vercel": {
		label: "Vercel",
		fields: []guidedSecretField{
			{name: "token", label: "Access token", placeholder: "paste token", secret: true},
			{name: "teamId", label: "Team ID", placeholder: "team_…"},
		},
	},
	"zoom": {
		label: "Zoom",
		fields: []guidedSecretField{
			{name: "accountId", label: "Account ID", placeholder: "paste account ID"},
			{name: "clientId", label: "Client ID", placeholder: "paste client ID"},
			{name: "clientSecret", label: "Client secret", placeholder: "paste client secret", secret: true},
		},
	},
}

func GuidedIntegrationNames() []string {
	names := make([]string, 0, len(guidedSecretSpecs))
	for name := range guidedSecretSpecs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func Secret() (SecretResult, bool, error) {
	labels := []string{"Integration", "Secret name", "Secret value"}
	placeholders := []string{"github", "token", "paste secret"}
	inputs := make([]textinput.Model, len(labels))
	for index := range labels {
		input := textinput.New()
		input.Prompt = labels[index] + "\n  "
		input.Placeholder = placeholders[index]
		input.CharLimit = 4096
		input.Width = 76
		if index == 2 {
			input.EchoMode = textinput.EchoPassword
			input.EchoCharacter = '•'
		}
		inputs[index] = input
	}
	inputs[0].Focus()
	result, err := tea.NewProgram(secretModel{
		inputs:      inputs,
		title:       "Store integration secret",
		description: "The value is masked and encrypted locally before it is written.",
	}, tea.WithAltScreen()).Run()
	if err != nil {
		return SecretResult{}, false, err
	}
	final := result.(secretModel)
	if final.cancelled || !final.done {
		return SecretResult{}, false, nil
	}
	return SecretResult{
		Integration: strings.ToLower(strings.TrimSpace(final.inputs[0].Value())),
		Name:        strings.TrimSpace(final.inputs[1].Value()),
		Value:       final.inputs[2].Value(),
	}, true, nil
}

func GuidedSecrets(integration string) (GuidedSecretResult, bool, error) {
	integration = strings.ToLower(strings.TrimSpace(integration))
	spec, ok := guidedSecretSpecs[integration]
	if !ok {
		return GuidedSecretResult{}, false, fmt.Errorf(
			"guided setup is unavailable for %q; choose one of: %s",
			integration,
			strings.Join(GuidedIntegrationNames(), ", "),
		)
	}
	inputs := make([]textinput.Model, len(spec.fields))
	for index, field := range spec.fields {
		input := textinput.New()
		input.Prompt = field.label + "\n  "
		input.Placeholder = field.placeholder
		input.CharLimit = 262144
		input.Width = 76
		if field.secret {
			input.EchoMode = textinput.EchoPassword
			input.EchoCharacter = '•'
		}
		inputs[index] = input
	}
	inputs[0].Focus()
	result, err := tea.NewProgram(secretModel{
		inputs:      inputs,
		title:       "Configure " + spec.label,
		description: "All required values are saved together in the encrypted local vault.",
	}, tea.WithAltScreen()).Run()
	if err != nil {
		return GuidedSecretResult{}, false, err
	}
	final := result.(secretModel)
	if final.cancelled || !final.done {
		return GuidedSecretResult{}, false, nil
	}
	values := make(map[string]string, len(spec.fields))
	for index, field := range spec.fields {
		values[field.name] = strings.TrimSpace(final.inputs[index].Value())
	}
	return GuidedSecretResult{Integration: integration, Values: values}, true, nil
}

type secretModel struct {
	inputs      []textinput.Model
	title       string
	description string
	action      string
	focus       int
	cancelled   bool
	done        bool
}

func (m secretModel) Init() tea.Cmd { return textinput.Blink }

func (m secretModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := message.(tea.KeyMsg); ok {
		switch key.String() {
		case "ctrl+c", "esc":
			m.cancelled = true
			return m, tea.Quit
		case "tab", "shift+tab", "enter", "up", "down":
			if key.String() == "enter" && m.focus == len(m.inputs)-1 {
				m.done = true
				return m, tea.Quit
			}
			m.inputs[m.focus].Blur()
			if key.String() == "shift+tab" || key.String() == "up" {
				m.focus--
			} else {
				m.focus++
			}
			if m.focus < 0 {
				m.focus = len(m.inputs) - 1
			}
			if m.focus >= len(m.inputs) {
				m.focus = 0
			}
			return m, m.inputs[m.focus].Focus()
		}
	}
	commands := make([]tea.Cmd, len(m.inputs))
	for index := range m.inputs {
		m.inputs[index], commands[index] = m.inputs[index].Update(message)
	}
	return m, tea.Batch(commands...)
}

func (m secretModel) View() string {
	view := brand.Render("◆") + "  " + title.Render(m.title) + "\n"
	view += mutedStyle.Render(m.description) + "\n\n"
	for index := range m.inputs {
		view += m.inputs[index].View() + "\n\n"
	}
	action := m.action
	if action == "" {
		action = "encrypt"
	}
	view += active.Render("Enter") + " " + action + "  •  " + mutedStyle.Render("tab next  •  esc cancel")
	return panel.Width(86).Render(view)
}

func Setup(initial SetupResult) (SetupResult, bool, error) {
	labels := []string{"iamly.io control-plane URL", "Beacon name", "Enrollment token"}
	values := []string{initial.Data.ControlPlane.URL, initial.Data.ControlPlane.BeaconName, ""}
	placeholders := []string{"https://beacon-dev.iamly.io", "Development Beacon", "paste token from iamly.io (blank keeps current identity)"}
	description := "The vault is encrypted with a local key stored beside it with restrictive permissions."
	if initial.Provider == vault.ProviderGoogleKMS {
		labels = append([]string{"Google Cloud KMS CryptoKey resource"}, labels...)
		values = append([]string{initial.KeyName}, values...)
		placeholders = append([]string{"projects/acme/locations/global/keyRings/iamly/cryptoKeys/beacon-vault"}, placeholders...)
		description = "The vault is encrypted locally. Google Cloud KMS wraps only its data-encryption key."
	} else if initial.Provider == vault.ProviderAWSKMS {
		labels = append([]string{"AWS KMS key ARN, key ID, or alias"}, labels...)
		values = append([]string{initial.KeyName}, values...)
		placeholders = append([]string{"arn:aws:kms:us-east-1:123456789012:key/…"}, placeholders...)
		description = "The vault is encrypted locally. AWS KMS wraps only its data-encryption key."
	}
	inputs := make([]textinput.Model, len(labels))
	for index := range labels {
		input := textinput.New()
		input.Prompt = labels[index] + "\n  "
		input.Placeholder = placeholders[index]
		input.SetValue(values[index])
		input.CharLimit = 512
		input.Width = 76
		if index == len(labels)-1 {
			input.EchoMode = textinput.EchoPassword
			input.EchoCharacter = '•'
		}
		inputs[index] = input
	}
	inputs[0].Focus()
	model := secretModel{
		inputs:      inputs,
		title:       "Configure Beacon",
		description: description,
		action:      "configure",
	}
	result, err := tea.NewProgram(model, tea.WithAltScreen()).Run()
	if err != nil {
		return SetupResult{}, false, err
	}
	final := result.(secretModel)
	if final.cancelled || !final.done {
		return SetupResult{}, false, nil
	}
	data := initial.Data
	if data.Integrations == nil {
		data.Integrations = make(map[string]map[string]string)
	}
	keyOffset := 0
	keyName := vault.LocalKeyName
	if initial.Provider != vault.ProviderLocal {
		keyOffset = 1
		keyName = strings.TrimSpace(final.inputs[0].Value())
	}
	data.ControlPlane.URL = strings.TrimRight(strings.TrimSpace(final.inputs[keyOffset].Value()), "/")
	data.ControlPlane.BeaconName = strings.TrimSpace(final.inputs[keyOffset+1].Value())
	return SetupResult{
		Provider:        initial.Provider,
		KeyName:         keyName,
		Data:            data,
		EnrollmentToken: strings.TrimSpace(final.inputs[keyOffset+2].Value()),
	}, true, nil
}
