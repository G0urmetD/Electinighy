<img src="/images/Electinighy.png" alt="Electinighy" width="200" height="200" /></a>

# Electinighy
Electinighy is a shell tool for updating an on-premise ELK cluster via apt repository. It supports updating ELK clusters in major versions 8 &amp; 9.

## Features
- ✅ Supports updates to specific ELK versions (e.g. `8.18.1`)
- ✅ Supports ELK major versions 8 & 9
- ✅ Colored CLI output for `[INFO]`, `[WARN]`, `[ERROR]`
- ✅ API key and APT repository validation
- ✅ Debug mode available
- ✅ Full logging under `/var/log/elk-update/`
- ✅ Optional port configuration for NAT or custom setups

## Requirements
- Debian-based distribution with `apt`
- Root permissions to manage service and packages
- Valid API Key with access to Elasticsearch & Kibana

## Example
Start with required cli parameters:
```bash
sudo ./electinighy.sh -a <API-KEY> -v 8.18.1 -eip 10.10.10.1
```

## Logging
Logs are written to `/var/log/elk-update/`:
- `update_elk_YYYYMMDD_HHMMSS.log` - general upgrade log
- `debug_elk_YYYYMMDD_HHMMSS.log` - verbose curl output (debug mode)

## Usage
```bash
8888888888 888                   888    d8b          d8b          888
888        888                   888    Y8P          Y8P          888
888        888                   888                              888
8888888    888  .d88b.   .d8888b 888888 888 88888b.  888  .d88b.  88888b.  888  888
888        888 d8P  Y8b d88P"    888    888 888 "88b 888 d88P"88b 888 "88b 888  888
888        888 88888888 888      888    888 888  888 888 888  888 888  888 888  888
888        888 Y8b.     Y88b.    Y88b.  888 888  888 888 Y88b 888 888  888 Y88b 888
8888888888 888  "Y8888   "Y8888P  "Y888 888 888  888 888  "Y88888 888  888  "Y88888
                                                              888               888
                                                         Y8b d88P          Y8b d88P
                                                          "Y88P"            "Y88P"
version: 0.7-beta Usage: ./elk-update.sh [OPTIONS]

Required Parameters:
  -a, --api-key     <API_KEY>        API key for authentication
  -v, --version     <VERSION>        Target ELK version (e.g., 8.18.1)
  -eip, --es-ip     <IP>             Elasticsearch IP address

Optional Parameters:
  -esp, --es-port   <PORT>           Elasticsearch port (default: 9200)
  -kip, --kb-ip     <IP>             Kibana IP address (default: same as --es-ip)
  -kp, --kb-port    <PORT>           Kibana port (default: 5601)
  -d, --debug                        Enables the debug mode for logging.
  -wt, --wait-time  <SECONDS>        Optional wait time before shutdown (default: 60s)

  -h, --help                         Show this help message and exit
```

## Parameters
### Required Parameters

| Short Option | Long Option     | Value         | Description                              |
|--------------|-----------------|---------------|------------------------------------------|
| `-a`         | `--api-key`     | `<API_KEY>`   | API key for authentication               |
| `-v`         | `--version`     | `<VERSION>`   | Target version for Elasticsearch/Kibana  |
| `-eip`       | `--es-ip`       | `<IP>`        | IP address of the Elasticsearch node     |

### Optional Parameters

| Short Option | Long Option     | Value         | Default       | Description                                       |
|--------------|-----------------|---------------|---------------|---------------------------------------------------|
| `-esp`       | `--es-port`     | `<PORT>`      | `9200`        | Elasticsearch port                                |
| `-kip`       | `--kb-ip`       | `<IP>`        | Same as ES IP | IP address of the Kibana instance                 |
| `-kp`        | `--kb-port`     | `<PORT>`      | `5601`        | Kibana port                                       |
| `-wt`        | `--wait-time`   | `<SECONDS>`   | `60`          | Wait time before shutdown (e.g., after shard disable) |
| `-d`         | `--debug`       | *(none)*      | `off`         | Enable debug mode with detailed curl logging      |
| `-h`         | `--help`        | *(none)*      | —             | Show help message                                 |


