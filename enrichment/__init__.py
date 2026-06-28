"""Asset enrichment modules.

Each module is independent and can be called individually:

* ``cloud``       – cloud/CDN/WAF provider detection
* ``asn``         – ASN / organization / country lookups via DNS
* ``ssl``         – SSL certificate metadata extraction
* ``whois``       – WHOIS / RDAP domain registration data
* ``shodan``      – Shodan host enrichment (requires API key)
* ``virustotal``  – VirusTotal reputation (requires API key)

All modules follow the same contract:

    enrich(host: str, **kwargs) -> Dict[str, Any]

They return a flat dict of enrichment data, or an empty dict on failure.
They MUST NEVER raise exceptions — enrichment is best-effort.
"""
