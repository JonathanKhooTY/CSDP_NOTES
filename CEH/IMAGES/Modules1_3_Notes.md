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

## Malware Components
**Crypter**: *Software that protects against reverse engineering* 

**Downloader**: *Trojan that download other malware onto host*

**Dropper**: *Trojan that **covertly** installs other malware in system*

**Exploit**: *Exploit.**The exploit carries the payload***

**Injector**: *Program that injects exploits or malicious code in malware into other vulnerable running processes and changes method of execution to hide or prevent removal*

**Obfuscator**: *Program that conceals malicious code of malware*

**Packer**: *Software that compresses malware file to convert code and data into unreadable format*

**Payload**: *Payload. The item which actually does the damage. **The exploit carries the payload***

**Malicious Code**: *Fundamental code that defines basic functionality of malware. May take form of Java Applets, ActiveX Controls, Browser Plugins etc*




