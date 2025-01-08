from scapy.all import *

#send 1 ICMP packet to github.com
send(IP(dst="github.com")/ICMP())

#receive packets
#sniff(filter="icmp", prn=lambda x : x.show())
"""
###[ Ethernet ]###
  dst       = 00:45:e2:5b:43:bb
  src       = 44:33:4c:f3:24:cf
  type      = IPv4   
###[ IP ]###
     version   = 4   
     ihl       = 5   
     tos       = 0x0 
     len       = 28  
     id        = 6121
     flags     =     
     frag      = 0   
     ttl       = 52  
     proto     = icmp
     chksum    = 0x9895
     src       = 140.82.121.4
     dst       = 192.168.16.100
        chksum    = 0x0
        id        = 0x0
        seq       = 0x0
        unused    = b''


"""

#send and receiving
#sr1(IP(dst="github.com")/ICMP())

#packet sniffing
#packets = sniff(count=10)
#packets.summary()
"""
Ether / IP / ICMP 140.82.121.4 > 192.168.16.100 echo-reply 0
Ether / IP / TCP 192.168.16.100:50157 > 20.42.73.24:https PA / Raw
Ether / IP / TCP 192.168.16.100:50157 > 20.42.73.24:https A / Raw       
Ether / IP / TCP 192.168.16.100:50157 > 20.42.73.24:https A / Raw       
Ether / IP / TCP 192.168.16.100:50157 > 20.42.73.24:https A / Raw       
Ether / IP / TCP 192.168.16.100:50157 > 20.42.73.24:https PA / Raw      
Ether / IP / TCP 20.42.73.24:https > 192.168.16.100:50157 A
Ether / IP / TCP 20.42.73.24:https > 192.168.16.100:50157 A
Ether / IP / TCP 20.42.73.24:https > 192.168.16.100:50157 A
Ether / IP / TCP 20.42.73.24:https > 192.168.16.100:50157 PA / Raw     
"""

#example: filter for http traffic
packets = sniff(filter = "tcp port 80", count=5)
packets.show()