# Bundled validated PoC source

`apache_cve_2021_41773.py` is the first versioned Stockpile item for the
synthetic PTaaS firing range. It targets the deliberately vulnerable Apache
HTTP Server 2.4.49 fixture. The normalized `run(payload)` entry point accepts
one payload, uses the assigned target and proxy environment, and returns
delivery status. It is not collected by the Stockpiler service at startup.

The PTaaS firing range seed reads this exact source, validates its Stockpile
contract, and stores it in the fixture PostgreSQL database as
`apache.cve-2021-41773-v1`. The item is selected only by an explicitly
authorized engagement; this repository does not enable it for production.
