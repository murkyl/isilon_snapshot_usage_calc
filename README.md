# OneFS snapshot usage calculator
Calculate the total capacity consumed by all snapshots given a directory path.

## Usage
```
python snapshot_usage_calc.py "/ifs" "/ifs/snapshottest"
Snapshot path: /ifs, size: 130.52 MiB
Snapshot path: /ifs/snapshottest, size: 1.61 GiB
```

```
python snapshot_usage_calc.py --server cluster.fqdn --user foo "/ifs" "/ifs/snapshottest"
Snapshot path: /ifs, size: 130.52 MiB
Snapshot path: /ifs/snapshottest, size: 1.61 GiB
```

### CLI options
Option|Description
------|-----------
-u, --user    |Optional user name to authenticate to the Isilon cluster. Used for off cluster execution. If user is not specified the script will prompt.
-p, --password|Optional password for the user specified above. Used for off cluster execution. If password is not specified the script will prompt.
-s, --server  |IP or FQDN of a cluster IP for the script to connect.
-e, --regex   |Enable regular expression path matching instead of exact string match.
--base10      |Enable size output in base 10 units instead of base 2 SI units.
--bytes       |Output size in bytes.
--precision   |Number of decimal places of precision for size output.
-l, --log     |Path to a log file.
--console_log |Output log to the console along with a possible file.
-q, --quiet   |Minimize screen output.
--debug       |Can be specified once or twice. One --debug will turn on INFO level messages while 2 --debug will turn on full debugging.
    
## Limitations and assumptions
* This script only works with OneFS versions 8.0 and above.
* When running the script on cluster, the currently user context will be used to for PAPI access.

## Authors
* Andrew Chung

## License
This project is licensed under the MIT License - see the LICENSE.md file for details