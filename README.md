**Fierce: Advanced Network Reconnaissance Tool**
=============================================

**Description**
---------------

Fierce is an advanced network reconnaissance tool that allows users to perform a variety of network reconnaissance tasks, including:

* Advanced DNS lookup
* Subdomain enumeration
* Port scanning
* WHOIS lookup
* SSL certificate information

**Features**
------------

* Advanced DNS lookup: retrieve information about a domain's DNS records, including A, AAAA, MX, NS, TXT, and CNAME records.
* Subdomain enumeration: discover hidden subdomains using a wordlist.
* Port scanning: scan open ports on a domain or network.
* WHOIS lookup: retrieve information about a domain's registration, including the registrar, creation date, and expiration date.
* SSL certificate information: retrieve information about a domain's SSL certificate, including the issuer, subject, version, and serial number.

**Usage**
-----

To use Fierce, simply run the script with the `python` command and provide the necessary arguments. For example:

```bash
python fierce.py -d example.com -v
```

This will perform an advanced DNS lookup, subdomain enumeration, port scanning, WHOIS lookup, and retrieve SSL certificate information for the domain `example.com`.

**Arguments**
-------------

* `-d`, `--domain`: specify the domain to investigate.
* `-s`, `--subnet`: specify the network to scan.
* `-v`, `--verbose`: enable verbose output.

**Requirements**
-------------

* Python 3.x
* `dns.resolver`, `ipaddress`, `concurrent.futures`, `requests`, `whois`, and `urllib.parse` libraries

**Credits**
------------

Fierce was created by [Rip70022/craxterpy](https://github.com/Rip70022).

**License**
------------

Fierce is distributed under the MIT License. See the `LICENSE` file for more information.
