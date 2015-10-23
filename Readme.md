Backsniffer
=====


Backsniffer is a covert communications suite comprised of a victim-side backdoor application and shell application that allows for an attacker to execute commands on a compromised system remotely.

Full assignment documentation including psuedocode, code listings & testing can be found in the docs folder

----------
Features
-----------
 - **Firewall Evasion** Commands are able to get through to the target machine even with a running firewall due to the use of raw-sockets to sniff for packets.
 - **Process Masking** The back-door module running on the client’s machine can camouflage itself by changing the name of it’s process. This allows it to remain invisible through usual detection methods such as running ‘ps aux’.
 - **Authentication** By checking for a pre-determined TTL and destination port, there are two layers of authentication to ensure that the backdoor only picks up messages that are meant for it.
 - **AES 256 Bit Encryption** All messages sent between the client and backdoor are encrypted using AES 256 bit encryption to mitigate any chance of easy discovery via packet captures.

Requirements & Limitations
----------------------------
1.	PyCrypto
2.	Setproctitle
3.	Scapy

Usage
-------
 1. Install dependancies ```sh install.sh```
 2. On the victims machine, start the application with the following command format: ```python client.py <listeningPort> <TTLkey> <16 Char Decryption Key>  <16 Char Initialization Vector> <ProcessName>``` i.e. ```python client.py 80 71 012345689abcdef abcdefghijklmnop [KWorker2:0]```
 3. On the attacker's machine, e.g. ```python blackhat.py <VictimIP> <SrcPort> <DstPort> <TTLkey> <16 Char Encryption Key> <16 Char Initialization Vector>```i.e. ```python blackhat.py 192.168.0.3 500 80 71 0123456789abcdef abcdefghijklmnop```
