package tui

import (
	"fmt"
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
	{"Configure", "Connect iamly.io and protect secrets with GCP KMS", Configure},
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
	KeyName         string
	Data            vault.Data
	EnrollmentToken string
}

type SecretResult struct {
	Integration string
	Name        string
	Value       string
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
	result, err := tea.NewProgram(secretModel{inputs: inputs}, tea.WithAltScreen()).Run()
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

type secretModel struct {
	inputs    []textinput.Model
	focus     int
	cancelled bool
	done      bool
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
	view := brand.Render("◆") + "  " + title.Render("Store integration secret") + "\n"
	view += mutedStyle.Render("The value is masked and encrypted locally before it is written.") + "\n\n"
	for index := range m.inputs {
		view += m.inputs[index].View() + "\n\n"
	}
	view += active.Render("Enter") + " encrypt  •  " + mutedStyle.Render("tab next  •  esc cancel")
	return panel.Width(86).Render(view)
}

type setupModel struct {
	inputs    []textinput.Model
	focus     int
	cancelled bool
	done      bool
}

func Setup(initial SetupResult) (SetupResult, bool, error) {
	labels := []string{"GCP KMS CryptoKey resource", "iamly.io control-plane URL", "Beacon name", "Enrollment token"}
	values := []string{initial.KeyName, initial.Data.ControlPlane.URL, initial.Data.ControlPlane.BeaconName, ""}
	placeholders := []string{
		"projects/acme/locations/global/keyRings/reviam/cryptoKeys/beacon-vault",
		"https://iamly.io", "Production Beacon", "paste token from iamly.io (blank keeps current identity)",
	}
	inputs := make([]textinput.Model, len(labels))
	for index := range labels {
		input := textinput.New()
		input.Prompt = labels[index] + "\n  "
		input.Placeholder = placeholders[index]
		input.SetValue(values[index])
		input.CharLimit = 512
		input.Width = 76
		if index == 3 {
			input.EchoMode = textinput.EchoPassword
			input.EchoCharacter = '•'
		}
		inputs[index] = input
	}
	inputs[0].Focus()
	model := setupModel{inputs: inputs}
	result, err := tea.NewProgram(model, tea.WithAltScreen()).Run()
	if err != nil {
		return SetupResult{}, false, err
	}
	final := result.(setupModel)
	if final.cancelled || !final.done {
		return SetupResult{}, false, nil
	}
	data := initial.Data
	if data.Integrations == nil {
		data.Integrations = make(map[string]map[string]string)
	}
	data.ControlPlane.URL = strings.TrimRight(strings.TrimSpace(final.inputs[1].Value()), "/")
	data.ControlPlane.BeaconName = strings.TrimSpace(final.inputs[2].Value())
	return SetupResult{
		KeyName:         strings.TrimSpace(final.inputs[0].Value()),
		Data:            data,
		EnrollmentToken: strings.TrimSpace(final.inputs[3].Value()),
	}, true, nil
}

func (m setupModel) Init() tea.Cmd { return textinput.Blink }

func (m setupModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
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

func (m setupModel) View() string {
	view := brand.Render("◆") + "  " + title.Render("Configure Beacon") + "\n"
	view += mutedStyle.Render("The vault is encrypted locally. GCP KMS only wraps its encryption key.") + "\n\n"
	for index := range m.inputs {
		view += m.inputs[index].View() + "\n\n"
	}
	view += active.Render("Enter") + " configure  •  " + mutedStyle.Render("tab next  •  esc cancel")
	return panel.Width(86).Render(view)
}
