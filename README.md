                                                                                           
# sx0tt-0-r3con

## Auto Recon Tool

A comprehensive automated reconnaissance tool that combines subdomain enumeration, URL probing, screenshot capture, and parameter discovery for bug bounty and penetration testing.

## Features

- **Subdomain Enumeration**: Uses Sublist3r for passive subdomain discovery
- **Fast DNS Bruteforce**: Custom high-speed DNS bruteforce with configurable wordlists
- **URL Probing**: Reliable curl-based HTTP/HTTPS endpoint discovery
- **Screenshot Capture**: GoWitness integration for visual reconnaissance
- **Parameter Discovery**: Arjun integration for hidden parameter detection
- **Progress Reporting**: Real-time progress updates for all operations
- **Error Handling**: Robust error handling with graceful fallbacks

## Installation

### Prerequisites

```bash
# Install required Python packages
pip install sublist3r

# Optional tools for full functionality
sudo apt install gowitness arjun
```

### SecLists Wordlists (Recommended)

```bash
sudo apt install seclists
# Or download manually:
# git clone https://github.com/danielmiessler/SecLists.git
```

## Usage

### Basic Usage

```bash
# Simple passive enumeration
python3 auto_recon.py example.com

# Specify output directory
python3 auto_recon.py example.com --output my_recon_results
```

### Advanced Options

```bash
# Full reconnaissance with all features
python3 auto_recon.py target.com --threads 40 --output target_recon

# Fast bruteforce with custom wordlist (recommended)
python3 auto_recon.py target.com \
    --wordlist /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    --wordlist-limit 2000 \
    --dns-timeout 1.5 \
    --threads 50 \
    --output target_fast

# Skip specific tools
python3 auto_recon.py target.com --skip-gowitness --skip-arjun

# High-performance scan
python3 auto_recon.py target.com \
    --wordlist /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
    --wordlist-limit 10000 \
    --dns-timeout 1.0 \
    --threads 100 \
    --arjun-threads 20
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `domain` | Target domain to enumerate | Required |
| `--threads` | Number of threads for Sublist3r | 40 |
| `--output` | Directory to store results | recon_output |
| `--arjun-threads` | Number of threads for Arjun | 10 |
| `--wordlist` | Wordlist file for DNS bruteforce | None |
| `--wordlist-limit` | Limit wordlist entries for speed | 5000 |
| `--dns-timeout` | DNS query timeout (seconds) | 2.0 |
| `--skip-gowitness` | Skip screenshot capture | False |
| `--skip-arjun` | Skip parameter discovery | False |

## Output Structure

```
target_recon/
├── subdomains.txt          # Discovered subdomains
├── urls.txt               # Responsive HTTP/HTTPS URLs
├── gowitness/            # Screenshots directory
│   ├── *.jpeg           # Individual screenshots
│   └── gowitness.sqlite3 # GoWitness database
└── arjun_results/        # Parameter discovery results
    └── *.json           # Per-URL parameter findings
```

## Performance Optimization

### Speed vs Coverage Trade-offs

| Scenario | Wordlist Limit | DNS Timeout | Threads | Time |
|----------|---------------|-------------|---------|------|
| **Quick Scan** | 1000 | 1.0s | 50 | ~2-5 min |
| **Balanced** | 5000 | 1.5s | 40 | ~10-15 min |
| **Thorough** | 20000 | 2.0s | 30 | ~30-60 min |
| **Exhaustive** | 110000 | 2.0s | 20 | 2-6 hours |

### Recommended Wordlists

```bash
# Fast (top 1K-5K subdomains)
/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Balanced (top 20K subdomains)  
/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# Comprehensive (110K subdomains)
/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

## Example Commands

### Bug Bounty Quick Scan
```bash
# Fast initial reconnaissance
python3 auto_recon.py target.com \
    --wordlist /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    --wordlist-limit 2000 \
    --dns-timeout 1.0 \
    --threads 60 \
    --output target_quick
```

### Comprehensive Assessment
```bash
# Full reconnaissance with screenshots and parameters
python3 auto_recon.py target.com \
    --wordlist /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
    --threads 40 \
    --arjun-threads 15 \
    --output target_full
```

### Background Long-Running Scan
```bash
# Large wordlist scan in background
nohup python3 auto_recon.py target.com \
    --wordlist /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
    --wordlist-limit 50000 \
    --threads 30 \
    --output target_deep > recon.log 2>&1 &
```

## Features Breakdown

### DNS Bruteforce Speed Improvements

The tool includes a custom fast DNS bruteforce implementation that provides significant speed improvements over traditional tools:

- **Concurrent DNS lookups** using ThreadPoolExecutor
- **Configurable timeouts** (default 2.0s, recommended 1.0-1.5s for speed)
- **Progress reporting** every 500 queries
- **Memory efficient** wordlist loading with limits
- **Built-in DNS caching** via system resolver
- **Real-time results** showing found subdomains immediately

### Tool Integration

- **Sublist3r**: Passive subdomain enumeration from search engines
- **Custom DNS Bruteforce**: High-speed active subdomain discovery
- **Curl**: Reliable HTTP/HTTPS endpoint probing
- **GoWitness**: Screenshot capture and visual reconnaissance
- **Arjun**: Hidden parameter discovery for found endpoints

## Troubleshooting

### Common Issues

1. **DNS timeouts**: Reduce `--dns-timeout` to 1.0 or increase to 3.0
2. **Rate limiting**: Reduce `--threads` to 20-30
3. **Memory usage**: Reduce `--wordlist-limit` 
4. **GoWitness errors**: Use `--skip-gowitness` if not needed
5. **Long execution time**: Use smaller wordlist limits for faster results

### Performance Tips

- Use `--wordlist-limit 2000-5000` for quick scans
- Set `--dns-timeout 1.0` for speed, `2.0+` for reliability  
- Use 50-100 threads for fast networks, 20-40 for slower connections
- Skip GoWitness/Arjun with flags if only subdomain enum needed

## License

This tool is for authorized security testing only. Users are responsible for ensuring they have permission to test target domains.
