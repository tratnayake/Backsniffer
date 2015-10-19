Instructions

1. Install dependancies
  sh startup.sh

2. Drop Firewall rules if you want to make sure it's raw.
  iptables -P INPUT DROP
  iptables -P OUTPUT DROP

3. On the blackhat:
   Command Format is:
   python blackhat.py <TargetIP> <srcPort> <dstPort> <TTL> <encryptionKey> <Initilization Vector>

   Example command if target IP is 192.168.0.3
   python blackhat.py 192.168.0.3 500 80 71 0123456789abcdef abcdefghijklmnop

 4. On the client
    Command Format is:
    python client.py <listeningPort> <TTL> <decryptionKey> <Initialization Vector>
    (Decryption keys and Initilization vectors must be the same on Client and blackhat)

    Example command is:
    python client.py 80 71 012345689abcdef abcdefghijklmnop [KWorker2:0]
