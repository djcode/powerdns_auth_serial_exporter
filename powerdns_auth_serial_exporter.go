package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	namespace        = "powerdns"
	apiInfoEndpoint  = "servers/localhost"
	apiZonesEndpoint = "servers/localhost/zones"
)

var (
	client = &http.Client{
		Transport: &http.Transport{
			Dial: func(netw, addr string) (net.Conn, error) {
				c, err := net.DialTimeout(netw, addr, 5*time.Second)
				if err != nil {
					return nil, err
				}
				if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					return nil, err
				}
				return c, nil
			},
		},
	}
)

// ServerInfo is used to parse JSON data from 'server/localhost' endpoint
type ServerInfo struct {
	Kind       string `json:"type"`
	ID         string `json:"id"`
	URL        string `json:"url"`
	DaemonType string `json:"daemon_type"`
	Version    string `json:"version"`
	ConfigUrl  string `json:"config_url"`
	ZonesUrl   string `json:"zones_url"`
}

type ZoneEntry struct {
	Item interface{}
}

type ZoneItem struct {
	Name            string  `json:"name"`
	Kind            string  `json:"kind"`
	Serial          float64 `json:"serial"`
	Notified_Serial float64 `json:"notified_serial"`
	Edited_Serial   float64 `json:"edited_serial"`
}

func (d *ZoneEntry) UnmarshalJSON(data []byte) error {
	d.Item = new(ZoneItem)
	return json.Unmarshal(data, d.Item)
}

// Exporter collects PowerDNS zones from the given HostURL and exports them using
// the prometheus metrics package.
type Exporter struct {
	HostURL    *url.URL
	ServerType string
	ApiKey     string
	mutex      sync.RWMutex

	up                prometheus.Gauge
	totalScrapes      prometheus.Counter
	jsonParseFailures prometheus.Counter
	serials           *prometheus.GaugeVec
	notified_serials  *prometheus.GaugeVec
	edited_serials    *prometheus.GaugeVec
}

// NewExporter returns an initialized Exporter.
func NewExporter(apiKey, serverType string, serverVersion *version.Version, hostURL *url.URL) *Exporter {
	return &Exporter{
		HostURL:    hostURL,
		ServerType: serverType,
		ApiKey:     apiKey,
		up: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: serverType,
			Name:      "up",
			Help:      "Was the last scrape of PowerDNS successful.",
		}),
		totalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: serverType,
			Name:      "exporter_total_scrapes",
			Help:      "Current total PowerDNS scrapes.",
		}),
		jsonParseFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: serverType,
			Name:      "exporter_json_parse_failures",
			Help:      "Number of errors while parsing PowerDNS JSON stats.",
		}),
		serials: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "zones",
			Name:      "serial",
			Help:      "Zone serial"}, []string{"zone", "kind"}),
		notified_serials: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "zones",
			Name:      "notified_serial",
			Help:      "Notified Serial"}, []string{"zone", "kind"}),
		edited_serials: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "zones",
			Name:      "edited_serial",
			Help:      "Edited Serial"}, []string{"zone", "kind"}),
	}
}

// Describe describes all the metrics ever exported by the PowerDNS exporter. It
// implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.up.Desc()
	ch <- e.totalScrapes.Desc()
	ch <- e.jsonParseFailures.Desc()
	prometheus.DescribeByCollect(e.serials, ch)
	prometheus.DescribeByCollect(e.notified_serials, ch)
	prometheus.DescribeByCollect(e.edited_serials, ch)
}

// Collect fetches the stats from configured PowerDNS API URI and delivers them
// as Prometheus metrics. It implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	scrape := e.scrape()
	ch <- e.up
	ch <- e.totalScrapes
	ch <- e.jsonParseFailures
	e.collectMetrics(ch, scrape)
}

func (e *Exporter) scrape() []ZoneEntry {
	e.totalScrapes.Inc()

	var data []ZoneEntry
	url := apiURL(e.HostURL, apiZonesEndpoint)
	err := getJSON(url, e.ApiKey, &data)
	if err != nil {
		e.up.Set(0)
		e.jsonParseFailures.Inc()
		log.Printf("Error scraping PowerDNS: %v", err)
		return nil
	}
	e.up.Set(1)
	return data
}

func (e *Exporter) collectMetrics(ch chan<- prometheus.Metric, zones []ZoneEntry) {
	for _, s := range zones {
		switch item := s.Item.(type) {
		case *ZoneItem:
			e.serials.WithLabelValues(item.Name, item.Kind).Set(item.Serial)
			e.notified_serials.WithLabelValues(item.Name, item.Kind).Set(item.Notified_Serial)
			e.edited_serials.WithLabelValues(item.Name, item.Kind).Set(item.Edited_Serial)
		}
	}
	e.serials.Collect(ch)
	e.notified_serials.Collect(ch)
	e.edited_serials.Collect(ch)
}

func getServerInfo(hostURL *url.URL, apiKey string) (*ServerInfo, error) {
	var info ServerInfo
	url := apiURL(hostURL, apiInfoEndpoint)
	err := getJSON(url, apiKey, &info)
	if err != nil {
		return nil, err
	}

	return &info, nil
}

func getJSON(url, apiKey string, data interface{}) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Add("X-API-Key", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		content, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf(string(content))
	}

	if err := json.NewDecoder(resp.Body).Decode(data); err != nil {
		return err
	}

	return nil
}

func apiURL(hostURL *url.URL, path string) string {
	endpointURI, _ := url.Parse(path)
	u := hostURL.ResolveReference(endpointURI)
	return u.String()
}

func main() {
	var (
		listenAddress = flag.String("listen-address", ":9120", "Address to listen on for web interface and telemetry.")
		metricsPath   = flag.String("metric-path", "/metrics", "Path under which to expose metrics.")
		apiURL        = flag.String("api-url", "http://localhost:8081/api/v1/", "Base-URL of PowerDNS authoritative server API.")
		apiKey        = flag.String("api-key", "", "PowerDNS API Key")
	)
	flag.Parse()

	hostURL, err := url.Parse(*apiURL)
	if err != nil {
		log.Fatalf("Error parsing api-url: %v", err)
	}

	server, err := getServerInfo(hostURL, *apiKey)
	if err != nil {
		log.Fatalf("Could not fetch PowerDNS server info: %v", err)
	}

	version, err := version.NewVersion(server.Version)
	if err != nil {
		log.Fatalf("Could not parse PowerDNS server version: %v", err)
	}

	exporter := NewExporter(*apiKey, server.DaemonType, version, hostURL)
	prometheus.MustRegister(exporter)

	log.Printf("Starting Server: %s", *listenAddress)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>PowerDNS Auth Serials Exporter</title></head>
             <body>
             <h1>PowerDNS Auth Serials Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})

	go func() {
		log.Fatal(http.ListenAndServe(*listenAddress, nil))
	}()

	<-stop
}
