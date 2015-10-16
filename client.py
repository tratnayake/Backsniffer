import sys
from scapy.all import *

global clientIP

knockCounter = 0;
def knockFilter1(packet):
    print "Stage 1"
    global clientIP
    clientIP = packet[IP].src
    print "Client IP is %s"%(clientIP)
    return True
def knockFilter2(packet):
    print "Stage 2"
    print "Client IP is %s"%(clientIP)
    return True

def knockFilter3(packet):
    print "Client IP is %s"%(clientIP)
    print "PORT KNOCK COMPLETE!"
    return True


#As a client, listen for the port knocks

sniff(filter='udp and dst port 514', stop_filter=knockFilter1)
sniff(filter='udp and dst port 515', stop_filter=knockFilter2)
sniff(filter='udp and dst port 516', stop_filter=knockFilter3)

print "GOT HERE!"
command = raw_input()
