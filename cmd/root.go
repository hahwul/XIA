package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/hahwul/dalfox/v2/pkg/har"
	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/hahwul/dalfox/v2/pkg/printing"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/cobra"
)

var options model.Options
var harFilePath string
var args Args

var rootCmd = &cobra.Command{
	Use: "dalfox",
	Run: func(cmd *cobra.Command, args []string) {
		printing.Banner(options)
		printing.DalLog("YELLOW", "Read the help page using the -h flag to see other options and flags!", options)
	},
}

// Execute is run rootCmd
func Execute() {
	defer func() {
		if options.HarWriter != nil {
			options.HarWriter.Close()
		}
	}()

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Slice
	rootCmd.PersistentFlags().StringSliceVarP(&args.Header, "header", "H", []string{}, "Add custom headers to the request. Example: -H 'Authorization: Bearer <token>'")
	rootCmd.PersistentFlags().StringSliceVarP(&args.P, "param", "p", []string{}, "Specify parameters to test. Example: -p 'username' -p 'password'")
	rootCmd.PersistentFlags().StringSliceVar(&args.IgnoreParams, "ignore-param", []string{}, "Ignore specific parameters during scanning. Example: --ignore-param 'api_token' --ignore-param 'csrf_token'")

	// String
	rootCmd.PersistentFlags().StringVar(&args.Config, "config", "", "Load configuration from a file. Example: --config 'config.json'")
	rootCmd.PersistentFlags().StringVarP(&args.Cookie, "cookie", "C", "", "Add custom cookies to the request. Example: -C 'sessionid=abc123'")
	rootCmd.PersistentFlags().StringVarP(&args.Data, "data", "d", "", "Use POST method and add body data. Example: -d 'username=admin&password=admin'")
	rootCmd.PersistentFlags().StringVar(&args.CustomPayload, "custom-payload", "", "Load custom payloads from a file. Example: --custom-payload 'payloads.txt'")
	rootCmd.PersistentFlags().StringVar(&args.CustomAlertValue, "custom-alert-value", "1", "Set a custom alert value. Example: --custom-alert-value 'document.cookie'")
	rootCmd.PersistentFlags().StringVar(&args.CustomAlertType, "custom-alert-type", "none", "Set a custom alert type. Example: --custom-alert-type 'str,none'")
	rootCmd.PersistentFlags().StringVar(&args.UserAgent, "user-agent", "", "Set a custom User-Agent header. Example: --user-agent 'Mozilla/5.0'")
	rootCmd.PersistentFlags().StringVarP(&args.Blind, "blind", "b", "", "Specify a blind XSS callback URL. Example: -b 'https://your-callback-url.com'")
	rootCmd.PersistentFlags().StringVarP(&args.Output, "output", "o", "", "Write output to a file. Example: -o 'output.txt'")
	rootCmd.PersistentFlags().StringVar(&args.Format, "format", "plain", "Set the output format. Supported: plain, json. Example: --format 'json'")
	rootCmd.PersistentFlags().StringVar(&args.FoundAction, "found-action", "", "Execute a command when a vulnerability is found. Example: --found-action './notify.sh'")
	rootCmd.PersistentFlags().StringVar(&args.FoundActionShell, "found-action-shell", "bash", "Specify the shell to use for the found action. Example: --found-action-shell 'bash'")
	rootCmd.PersistentFlags().StringVar(&args.Proxy, "proxy", "", "Send all requests through a proxy server. Example: --proxy 'http://127.0.0.1:8080'")
	rootCmd.PersistentFlags().StringVar(&args.Grep, "grep", "", "Use a custom grepping file. Example: --grep './samples/sample_grep.json'")
	rootCmd.PersistentFlags().StringVar(&args.IgnoreReturn, "ignore-return", "", "Ignore specific HTTP return codes. Example: --ignore-return '302,403,404'")
	rootCmd.PersistentFlags().StringVarP(&args.MiningWord, "mining-dict-word", "W", "", "Specify a custom wordlist file for parameter mining. Example: -W 'wordlist.txt'")
	rootCmd.PersistentFlags().StringVarP(&args.Method, "method", "X", "GET", "Override the HTTP method. Example: -X 'PUT'")
	rootCmd.PersistentFlags().StringVarP(&args.CookieFromRaw, "cookie-from-raw", "", "", "Load cookies from a raw HTTP request file. Example: --cookie-from-raw 'request.txt'")
	rootCmd.PersistentFlags().StringVar(&args.RemotePayloads, "remote-payloads", "", "Use remote payloads for XSS testing. Supported: portswigger, payloadbox. Example: --remote-payloads 'portswigger,payloadbox'")
	rootCmd.PersistentFlags().StringVar(&args.RemoteWordlists, "remote-wordlists", "", "Use remote wordlists for parameter mining. Supported: burp, assetnote. Example: --remote-wordlists 'burp'")
	rootCmd.PersistentFlags().StringVar(&args.OnlyPoC, "only-poc", "", "Show only the PoC code for the specified pattern. Supported: g (grep), r (reflected), v (verified). Example: --only-poc 'g,v'")
	rootCmd.PersistentFlags().StringVar(&args.PoCType, "poc-type", "plain", "Select the PoC type. Supported: plain, curl, httpie, http-request. Example: --poc-type 'curl'")
	rootCmd.PersistentFlags().StringVar(&args.ReportFormat, "report-format", "plain", "Set the format of the report. Supported: plain, json. Example: --report-format 'json'")
	rootCmd.PersistentFlags().StringVar(&args.HarFilePath, "har-file-path", "", "Specify the path to save HAR files of scan requests. Example: --har-file-path 'scan.har'")

	// Int
	rootCmd.PersistentFlags().IntVar(&args.Timeout, "timeout", 10, "Set the request timeout in seconds. Example: --timeout 10")
	rootCmd.PersistentFlags().IntVar(&args.Delay, "delay", 0, "Set the delay between requests to the same host in milliseconds. Example: --delay 1000")
	rootCmd.PersistentFlags().IntVarP(&args.Concurrence, "worker", "w", 100, "Set the number of concurrent workers. Example: -w 100")
	rootCmd.PersistentFlags().IntVar(&args.MaxCPU, "max-cpu", 1, "Set the maximum number of CPUs to use. Example: --max-cpu 1")

	// Bool
	rootCmd.PersistentFlags().BoolVar(&args.OnlyDiscovery, "only-discovery", false, "Only perform parameter analysis, skip XSS scanning. Example: --only-discovery")
	rootCmd.PersistentFlags().BoolVarP(&args.Silence, "silence", "S", false, "Only print PoC code and progress. Example: -S")
	rootCmd.PersistentFlags().BoolVar(&args.Mining, "mining-dict", true, "Enable dictionary-based parameter mining. Example: --mining-dict")
	rootCmd.PersistentFlags().BoolVar(&args.FindingDOM, "mining-dom", true, "Enable DOM-based parameter mining. Example: --mining-dom")
	rootCmd.PersistentFlags().BoolVarP(&args.FollowRedirect, "follow-redirects", "F", false, "Follow HTTP redirects. Example: -F")
	rootCmd.PersistentFlags().BoolVar(&args.NoColor, "no-color", false, "Disable colorized output. Example: --no-color")
	rootCmd.PersistentFlags().BoolVar(&args.NoSpinner, "no-spinner", false, "Disable spinner animation. Example: --no-spinner")
	rootCmd.PersistentFlags().BoolVar(&args.UseBAV, "use-bav", false, "Enable Basic Another Vulnerability (BAV) analysis. Example: --use-bav")
	rootCmd.PersistentFlags().BoolVar(&args.SkipBAV, "skip-bav", false, "Skip Basic Another Vulnerability (BAV) analysis. Example: --skip-bav")
	rootCmd.PersistentFlags().BoolVar(&args.SkipMiningDom, "skip-mining-dom", false, "Skip DOM-based parameter mining. Example: --skip-mining-dom")
	rootCmd.PersistentFlags().BoolVar(&args.SkipMiningDict, "skip-mining-dict", false, "Skip dictionary-based parameter mining. Example: --skip-mining-dict")
	rootCmd.PersistentFlags().BoolVar(&args.SkipMiningAll, "skip-mining-all", false, "Skip all parameter mining. Example: --skip-mining-all")
	rootCmd.PersistentFlags().BoolVar(&args.SkipXSSScan, "skip-xss-scanning", false, "Skip XSS scanning. Example: --skip-xss-scanning")
	rootCmd.PersistentFlags().BoolVar(&args.OnlyCustomPayload, "only-custom-payload", false, "Only test custom payloads. Example: --only-custom-payload")
	rootCmd.PersistentFlags().BoolVar(&args.SkipGrep, "skip-grepping", false, "Skip built-in grepping. Example: --skip-grepping")
	rootCmd.PersistentFlags().BoolVar(&args.Debug, "debug", false, "Enable debug mode and save all logs. Example: --debug")
	rootCmd.PersistentFlags().BoolVar(&args.SkipHeadless, "skip-headless", false, "Skip headless browser-based scanning (DOM XSS and inJS verification). Example: --skip-headless")
	rootCmd.PersistentFlags().BoolVar(&args.UseDeepDXSS, "deep-domxss", false, "Enable deep DOM XSS testing with more payloads (slow). Example: --deep-domxss")
	rootCmd.PersistentFlags().BoolVar(&args.OutputAll, "output-all", false, "Enable all log write mode (output to file or stdout). Example: --output-all")
	rootCmd.PersistentFlags().BoolVar(&args.WAFEvasion, "waf-evasion", false, "Enable WAF evasion by adjusting speed when detecting WAF (worker=1, delay=3s). Example: --waf-evasion")
	rootCmd.PersistentFlags().BoolVar(&args.ReportBool, "report", false, "Show detailed report. Example: --report")
	rootCmd.PersistentFlags().BoolVar(&args.OutputRequest, "output-request", false, "Include raw HTTP requests in the results. Example: --output-request")
	rootCmd.PersistentFlags().BoolVar(&args.OutputResponse, "output-response", false, "Include raw HTTP responses in the results. Example: --output-response")
	rootCmd.PersistentFlags().BoolVar(&args.SkipDiscovery, "skip-discovery", false, "Skip the entire discovery phase, proceeding directly to XSS scanning. Requires -p flag to specify parameters. Example: --skip-discovery -p 'username'")

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	stime := time.Now()
	au := aurora.NewAurora(!args.NoColor)
	options = model.Options{
		Header:            args.Header,
		Cookie:            args.Cookie,
		UniqParam:         args.P,
		BlindURL:          args.Blind,
		CustomPayloadFile: args.CustomPayload,
		CustomAlertValue:  args.CustomAlertValue,
		CustomAlertType:   args.CustomAlertType,
		Data:              args.Data,
		UserAgent:         args.UserAgent,
		OutputFile:        args.Output,
		Format:            args.Format,
		FoundAction:       args.FoundAction,
		FoundActionShell:  args.FoundActionShell,
		ProxyAddress:      args.Proxy,
		Grep:              args.Grep,
		IgnoreReturn:      args.IgnoreReturn,
		IgnoreParams:      args.IgnoreParams,
		Timeout:           args.Timeout,
		Concurrence:       args.Concurrence,
		MaxCPU:            args.MaxCPU,
		Delay:             args.Delay,
		OnlyDiscovery:     args.OnlyDiscovery,
		OnlyCustomPayload: args.OnlyCustomPayload,
		Silence:           args.Silence,
		FollowRedirect:    args.FollowRedirect,
		Scan:              make(map[string]model.Scan),
		Mining:            args.Mining,
		MiningWordlist:    args.MiningWord,
		FindingDOM:        args.FindingDOM,
		NoColor:           args.NoColor,
		Method:            args.Method,
		NoSpinner:         args.NoSpinner,
		NoBAV:             args.SkipBAV,
		NoGrep:            args.SkipGrep,
		Debug:             args.Debug,
		CookieFromRaw:     args.CookieFromRaw,
		AuroraObject:      au,
		StartTime:         stime,
		MulticastMode:     false,
		RemotePayloads:    args.RemotePayloads,
		RemoteWordlists:   args.RemoteWordlists,
		UseHeadless:       !args.SkipHeadless,
		UseDeepDXSS:       args.UseDeepDXSS,
		OnlyPoC:           args.OnlyPoC,
		OutputAll:         args.OutputAll,
		WAF:               false,
		WAFEvasion:        args.WAFEvasion,
		PoCType:           args.PoCType,
		ReportBool:        args.ReportBool,
		ReportFormat:      args.ReportFormat,
		OutputRequest:     args.OutputRequest,
		OutputResponse:    args.OutputResponse,
		UseBAV:            args.UseBAV,
		SkipDiscovery:     args.SkipDiscovery,
	}

	if args.HarFilePath != "" {
		initHarWriter()
	}

	if args.SkipMiningAll {
		options.FindingDOM = false
		options.Mining = false
	} else {
		if args.SkipMiningDom {
			options.FindingDOM = false
		}
		if args.SkipMiningDict {
			options.Mining = false
		}
	}

	if args.SkipXSSScan {
		options.OnlyDiscovery = true
	}

	if args.MaxCPU > 1 {
		runtime.GOMAXPROCS(args.MaxCPU)
	}

	if args.Grep != "" {
		loadFile(args.Grep, "grepping")
	}

	if args.Config != "" {
		loadFile(args.Config, "config option")
	}
}

func initHarWriter() {
	f, err := os.Create(harFilePath)
	if err != nil {
		fmt.Println(err)
	} else {
		options.HarWriter, err = har.NewWriter(f, &har.Creator{Name: "dalfox", Version: printing.VERSION})
		if err != nil {
			fmt.Println(err)
		}
	}
}

func loadFile(filePath, fileType string) {
	jsonFile, err := os.Open(filePath)
	if err != nil {
		fmt.Println(err)
		return
	}
	printing.DalLog("SYSTEM", "Loaded "+filePath+" file for "+fileType, options)
	defer jsonFile.Close()

	byteValue, _ := io.ReadAll(jsonFile)
	if fileType == "config option" {
		err = json.Unmarshal(byteValue, &options)
		if err != nil {
			printing.DalLog("SYSTEM", "Error while parsing config file", options)
		}
	} else {
		options.Grep = string(byteValue)
	}
}
