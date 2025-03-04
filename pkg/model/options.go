package model

import (
	"net/http"
	"sync"
	t "time"

	"github.com/hahwul/dalfox/v2/pkg/har"

	s "github.com/briandowns/spinner"
	a "github.com/logrusorgru/aurora"
)

// Options is struct of options
type Options struct {
	UniqParam         []string `json:"param,omitempty"`
	Cookie            string   `json:"cookie,omitempty"`
	Header            []string `json:"header,omitempty"`
	ConfigFile        string   `json:"config,omitempty"`
	BlindURL          string   `json:"blind,omitempty"`
	CustomPayloadFile string   `json:"custom-payload-file,omitempty"`
	CustomAlertValue  string   `json:"custom-alert-value,omitempty"`
	CustomAlertType   string   `json:"custom-alert-type,omitempty"`
	Data              string   `json:"data,omitempty"`
	UserAgent         string   `json:"user-agent,omitempty"`
	OutputFile        string   `json:"output,omitempty"`
	Format            string   `json:"format,omitempty"`
	FoundAction       string   `json:"found-action,omitempty"`
	FoundActionShell  string   `json:"found-action-shell,omitempty"`
	ProxyAddress      string   `json:"proxy,omitempty"`
	Grep              string   `json:"grep,omitempty"`
	IgnoreReturn      string   `json:"ignore-return,omitempty"`
	IgnoreParams      []string `json:"ignore-params,omitempty"`
	Trigger           string   `json:"trigger,omitempty"`
	Timeout           int      `json:"timeout,omitempty"`
	Concurrence       int      `json:"worker,omitempty"`
	MaxCPU            int      `json:"maxcpu,omitempty"`
	Delay             int      `json:"delay,omitempty"`
	AllURLS           int
	NowURL            int
	Sequence          int  `json:"sequence,omitempty"`
	OnlyDiscovery     bool `json:"only-discovery,omitempty"`
	OnlyCustomPayload bool `json:"only-custom-payload,omitempty"`
	Silence           bool `json:"silence,omitempty"`
	IsAPI             bool `json:"is-api,omitempty"`
	IsLibrary         bool `json:"is-library,omitempty"`
	Mass              bool `json:"mass,omitempty"`
	MulticastMode     bool `json:"multicast-mode,omitempty"`
	Scan              map[string]Scan
	FollowRedirect    bool   `json:"follow-redirects,omitempty"`
	Mining            bool   `json:"mining-dict,omitempty"`
	FindingDOM        bool   `json:"mining-dom,omitempty"`
	MiningWordlist    string `json:"mining-dict-word,omitempty"`
	NoColor           bool   `json:"no-color,omitempty"`
	Method            string `json:"method,omitempty"`
	TriggerMethod     string `json:"trigger-method,omitempty"`
	NoSpinner         bool   `json:"no-spinner,omitempty"`
	NoBAV             bool   `json:"no-bav,omitempty"`
	ServerHost        string `json:"server-host,omitempty"`
	ServerPort        int    `json:"server-port,omitempty"`
	NoGrep            bool   `json:"skip-grepping,omitempty"`
	Debug             bool   `json:"debug,omitempty"`
	CookieFromRaw     string `json:"cookie-from-raw,omitempty"`
	ScanResult        Result
	SpinnerObject     *s.Spinner
	AuroraObject      a.Aurora
	StartTime         t.Time
	HarWriter         *har.Writer
	PathReflection    map[int]string
	RemotePayloads    string `json:"remote-payloads,omitempty"`
	RemoteWordlists   string `json:"remote-wordlists,omitempty"`
	UseHeadless       bool   `json:"use-headless,omitempty"`
	UseDeepDXSS       bool   `json:"use-deepdxss,omitempty"`
	OnlyPoC           string `json:"only-poc,omitempty"`
	OutputAll         bool   `json:"output-all,omitempty"`
	WAF               bool
	WAFName           string `json:"waf-name,omitempty"`
	WAFEvasion        bool
	PoCType           string `json:"poc-type,omitempty"`
	Mutex             *sync.Mutex
	ReportFormat      string
	ReportBool        bool
	OutputRequest     bool `json:"output-request,omitempty"`
	OutputResponse    bool `json:"output-response,omitempty"`
	UseBAV            bool `json:"use-bav,omitempty"`
	CustomTransport   http.RoundTripper
	SkipDiscovery     bool `json:"skip-discovery,omitempty"`
}

// MassJob is list for mass
type MassJob struct {
	Name string
	URLs []string
}

// Scan is struct of scan
type Scan struct {
	URL     string
	ScanID  string
	Logs    []string
	Results []PoC
}

// Issue is struct of issue
type Issue struct {
	Type  string `json:"type"`
	Param string `json:"param"`
	PoC   PoC    `json:"poc"`
}
