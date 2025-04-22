# BGP Hijack Monitor for Wazuh (Mock Mode)

![Wazuh Integration](https://img.shields.io/badge/Wazuh-4.7.2-green)
![Mock Mode](https://img.shields.io/badge/Mock-Enabled-blue)

A containerized BGP hijack detector that generates **simulated hijack events** for testing Wazuh integrations without requiring live BGP data.

## Features

- **Realistic mock data generation**
  - Fake AS numbers (AS1000-AS9999)
  - Random IPv4 prefixes (1.1.0.0/16 to 254.254.0.0/16)
  - Configurable event frequency

- **Wazuh integration**
  - Native alerts through Wazuh API
  - Pre-configured custom rules (ID 900100)
  - MITRE ATT&CK T1574 tagging

- **Docker-Ready**
  - Pre-built compose configuration
  - Isolated service networking
  - Environment variable configuration

## Quick Start

```bash
# Clone and deploy
git clone https://github.com/your-repo/bgp-wazuh-monitor
cd bgp-wazuh-monitor
docker-compose up -d --build
```

```
# View mock alerts
docker exec wazuh-manager tail -f /var/ossec/logs/alerts/alerts.json | grep 'BGP Hijack'
```

## Mock Configuration

Customize in `bgp-detector/src/mock_stream.hpp`:

```cpp
// Generate 5 events per check (default: 3)
generate_events(5);

// AS number range (default: 1000-9999)
std::uniform_int_distribution<> asn_dist(5000, 20000); 

// Prefix generation (default: 1-254)
std::uniform_int_distribution<> prefix_dist(10, 200);
```

## Access interfaces

| Service	         | URL	                    | Credentials                   |
|------------------|-------------------------|-------------------------------|
| Wazuh Dashboard	 | https://localhost	      | admin/WAZUH_API_PASS          |
| Wazuh API	       | http://localhost:55000	 | WAZUH_API_USER/WAZUH_API_PASS |


## Sample Alert

```yaml
{
  "timestamp": "2024-03-20T15:32:45Z",
  "rule": {
    "id": 900100,
    "description": "BGP Hijack Detected (MOCK)",
    "level": 12
  },
  "bgp": {
    "hijacker_asn": "AS7890",
    "victim_prefix": "123.45.0.0/16",
    "is_mock": true
  }
}
```

## Switching to Production

To use real BGP data:

* Replace mock_stream.hpp with real API calls
* Set BGPSTREAM_API_KEY in .env
* Rebuild: 

```commandline
docker-compose build bgp-detector
```

## Troubleshooting

```
# Test Wazuh API connectivity
docker exec bgp-detector curl -k -u admin:StrongPassword123! http://wazuh-manager:55000

# View detector logs
docker-compose logs -f bgp-detector

# Force rule reload
docker exec wazuh-manager /var/ossec/bin/wazuh-control restart
```

## License

Apache 2.0




