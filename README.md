# IP ↔ Domain Intelligence Tool

A Streamlit-based web application for DNS intelligence and reverse lookup operations.

This tool enables bidirectional resolution between domain names and IP addresses, along with hosted domain enumeration using reverse IP lookup.

---

## Overview

The application provides three primary capabilities:

1. Domain → IP Address Resolution (A Record Lookup)
2. IP Address → Reverse DNS Lookup (PTR Record)
3. IP Address → Hosted Domain Enumeration (Reverse IP API)

It is suitable for:

- DNS diagnostics
- Infrastructure investigation
- OSINT exploration
- Security research
- Networking practice

---

## Architecture

### Domain Resolution Flow

Input Domain  
→ URL Normalization  
→ DNS A Record Query (dnspython)  
→ Return IPv4 Addresses  

### Reverse DNS Flow

Input IP Address  
→ Convert to Reverse DNS Format  
→ PTR Record Query  
→ Return Hostname(s)  

### Reverse IP Lookup Flow

Input IP Address  
→ External Reverse IP API Call  
→ Parse Response  
→ Display Hosted Domains  

---

## Technology Stack

- Python 3.x
- Streamlit
- dnspython
- requests

---

## Installation

Clone the repository:
```
git clone https://github.com/yourusername/ip-domain-intelligence-tool.git

cd ip-domain-intelligence-tool
```

---

Install dependencies:
```
pip install streamlit dnspython requests
```
or using requirements file:
```
pip install -r requirements.txt
```

---

## Running the Application

Start the Streamlit server:
```
streamlit run app.py
```

Open the local URL shown in the terminal (typically http://localhost:8501).

---

---

## Expected Behavior

### Domain Input Example

```
Input:
google.com

Output:
A Records:
142.250.xxx.xxx
```

---

### IP Input Example

Input:
8.8.8.8


Output:
PTR Record:
dns.google.

Hosted Domains:
example1.com
example2.com

---

## Important Technical Notes

- Reverse DNS (PTR) depends entirely on IP owner configuration.
- Many IP addresses do not have PTR records.
- Shared hosting IPs may host hundreds of domains.
- Reverse IP lookup depends on third-party API datasets.
- Free APIs may enforce rate limits.

Reverse DNS does NOT guarantee discovery of all domains hosted on an IP.

---

## Project Structure

.
├── app.py
├── requirements.txt
└── README.md

---

## Limitations

- IPv4 focused (no full IPv6 support)
- API-based reverse IP lookup may fail under rate limits
- No caching layer implemented
- No advanced DNS record inspection (MX, TXT, CNAME)

---

## Potential Enhancements

- IPv6 support
- DNS record explorer (MX, TXT, CNAME, NS)
- WHOIS integration
- ASN detection
- GeoIP lookup
- SSL certificate extraction
- Port scanning integration
- Async request optimization
- Docker deployment
- Production logging

---

## Disclaimer

This tool is intended for educational and research purposes only.

DNS data accuracy depends on upstream resolvers and external APIs.  
Use responsibly and comply with applicable laws and service provider terms.
