### `Detection technique`

- Phase 1 — service SIDs via LsarLookupNames
- Phase 2 — running processes via IPC$ pipes.
- Phase 3 — correlation.

### `Install`

- Python 3.8+ and impacket:

        pip install impacket

        git clone https://github.com/Alb4don/Spectra.git
        cd spectra
        python spectra.py --help

### `Usage`

- Password auth:

        python spectra.py -t 192.168.1.10 -u jsmith -p 'Summer2024!' -d CORP

- Pass the hash (single NT hash or full LM:NT pair):

        python spectra.py -t 192.168.1.10 -u jsmith \
        --nthash aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 \
        -d CORP

- Kerberos with explicit KDC:

        python spectra.py -t dc01.corp.local -u jsmith -d CORP.LOCAL \
        --kerberos --kdchost 10.0.0.1

- Bulk scan, threaded, JSON export:

        python spectra.py -T targets.txt -u jsmith -p 'Summer2024!' -d CORP \
        --threads 10 --json results.json

- Targets file: One host per line, # comments allowed.

            Flag             Purpose
            --threads       N	Concurrent host scans (default 5)
            --timeout S	    SMB timeout in seconds (default 30)
            --retries       N	Connection retry attempts (default 2)
            --port	        SMB port (default 445)
            -v	            Show each service query and pipe match
            --debug	        Add raw RPC error text to output
            --no-color	    Strip ANSI codes for piping or logging
            --json          FILE	Structured export of all findings

### `Coverage`

- Thirty two products ship with signatures, including CrowdStrike, SentinelOne, Microsoft Defender for Endpoint, Carbon Black (App Control and Cloud), Cortex XDR, Cybereason, Trellix/McAfee, Trend Micro, Sophos Intercept X, Symantec, Kaspersky, ESET, Bitdefender, FortiClient, FortiEDR, Panda, WithSecure, G Data, Malwarebytes, Avast/AVG, Check Point, Cynet, Elastic Defend, Rapid7, Wazuh, Ivanti, HarfangLab, Acronis, BlackBerry Cylance, and OpenEDR.
- The database is a snapshot. Vendors rename services between major versions. Entries are structured dicts in a single Python list, so extending it for a product you've observed is a few lines.
