# powerdns_auth_serial_exporter
A PowerDNS exporter specifically designed to export all zone serials as metrics for Prometheus.

PowerDNS Exporter (https://github.com/janeczku/powerdns_exporter) used heavily as the base.

## Build instructions
```
go get
go build
```

## Usage
```
Usage of ./powerdns_auth_serial_exporter:
  -api-key string
    	PowerDNS API Key
  -api-url string
    	Base-URL of PowerDNS authoritative server API. (default "http://localhost:8081/api/v1/")
  -listen-address string
    	Address to listen on for web interface and telemetry. (default ":9120")
  -metric-path string
    	Path under which to expose metrics. (default "/metrics")
```
