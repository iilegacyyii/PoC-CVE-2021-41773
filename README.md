# CVE-2021-41773 PoC

Proof of concept to check if hosts are vulnerable to CVE-2021-41773.

## Description (https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773)

A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49-2.4.50.  

An attacker could use a path traversal attack to map URLs to files outside the expected document root. If files outside of the document root are not protected by "require all denied" these requests can succeed. Additionally this flaw could leak the source of interpreted files like CGI scripts.

This issue only affects Apache 2.4.49 & 2.4.50 and not earlier versions.

## Patch

There are currently two methods:
1. Update Apache HTTP Server to a version >= 2.4.51
2. If the above is not possible, although not recommended as it doesn't guarantee a fix, edit the following in `/etc/apache2/apache2.conf`:
  ```xml
<!-- Vulnerable (Require all granted in '/') -->
<Directory />
	Options FollowSymLinks
	AllowOverride None
	Require all granted
</Directory>

<!-- Patched (Require all denied in '/') -->
<Directory />
	Options FollowSymLinks
	AllowOverride None
	Require all denied
</Directory>
```

## Usage

Use the script as follows:
```plaintext
CVE-2021-41773.py [-h] [--nosslcheck] [--cores CORES] [--file TARGETFILE] host

Checks if an apache server is vulnerable to CVE-2021-41773.

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           ip/domain to be checked e.g. 'https://google.com/'.
  --nosslcheck, -n      Do not verify ssl certificates.
  --cores CORES, -C CORES
                        Specify number of cores that should be dedicated to the task, default: 1
  --file TARGETFILE, -f TARGETFILE
                        Specify file to fetch list of hosts from, example: "/home/user/Desktop/myfile.txt"
  --rce, -r             When toggled checks if target is susceptible to RCE (NOT YET IMPLEMENTED!)
```
