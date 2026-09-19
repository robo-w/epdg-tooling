# 3GPP DNS Query

This folder contains helper scripts to query the ePDG DNS records.

Disclaimer: All tools are created with AI support.

## query_3gpp_dns.py

- Queries 3GPP operator DNS domains for A/AAAA and TXT records.

Install dependencies:

```bash
pip install -r requirements.txt
```

Run example:

```bash
python query_3gpp_dns.py --carriers 232-001 232-03
python query_3gpp_dns.py --file mnc_austria.txt --json > dns_austria.json
```

## compare_mnc_endpoints.py

- Parses DNS query JSON results and extracts de-duplicated records

Run example:

```bash
python compare_mnc_endpoints.py --file dns_austria.json
```
