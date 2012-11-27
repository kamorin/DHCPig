DHCPig
======

Note: *I am too lazy to write my own README - most of the work was done by kamorin with more info added by me*

Note2: *I hate global vars and I hate threading... and using global vars in combination with threading is like opening hells gates :) anyway as I forked this code I've adopted the style and will stick to it until I really have time to make this pep8 and rock solid. Please check my other repos for other DHCPv4/v6 implementations using a proper class layout or a statemachine.*

CHANGES
-------
* more options, double the fun: scapy fuzzing, ipv6 support
* more options, more fun: show options/show icmp/show arp
* fixed indents, beautify __doc__, eyefriendly one-line-logging
* __FORKED__ from __kamorin/DHCPig__ - Thanks for your work!

SUMMARY
-------

DHCPig initiates an advanced DHCP exhaustion attack. It will consume all IPs on the LAN, stop new users from obtaining IPs,
release any IPs in use, then for good measure send gratuitous ARP and knock all windows hosts offline.

It requires scapy >=2.1 library and admin privileges to execute. No configuration necessary, just pass the interface as 
a parameter. It has been tested on multiple Linux distributions and multiple DHCP servers (ISC,Windows 2k3/2k8,..).


When executed the script will perform the following actions:

* Grab your Neighbors IPs before they do   
	Listen for DHCP Requests from other clients if offer detected, respond with request for that offer.   

* Request all available IP addresses in Zone   
	Loop and Send DHCP Requests all from different hosts & MAC addresses  

* Find your Neighbors MAC & IP and release their IP from DHCP server   
	ARP for all neighbors on that LAN, then send DHCPReleases to server   
	

Finally the script will then wait for DHCP exhaustion, (that is no received DHCP OFFERs for 10 seconds)  and then 


* Knock all Windows systems offline   
	gratuitous ARP the LAN, and since no additional DHCP addresses are available these windows systems should stay 
offline.  Linux systems will not give up IP even when another system on LAN is detected with same IP.


PROTOCOL
--------
* __IPv4__
	 * SEQUENCE
		  1. ----> DHCP_DISCOVER 
		  2. <---- DHCP_OFFER    
		  3. ----> DHCP_REQUEST  
		  4. <---- DHCP_REPLY (ACK/NACK)	- not implemented
	 * DHCPd snoop detection (DHCPd often checks if IP is in use)
		  * Check for ARP_Snoops 
		  * Check for ICMP Snoops 

* __IPv6__
	* SEQUENCE
		1. ----> DHCP6_SOLICIT  
		2. <---- DHCP6_ADVERTISE 
		3. ----> DHCP6_REQUEST   
		4. <---- DHCP6_REPLY - not implemented    
	 * DHCPd snoop detection (DHCPd often checks if IP is in use)
	  	* Check for ICMPv6 Snoops 



USAGE
-----
enhanced DHCP exhaustion attack plus.   

	Usage:
	    pig.py [-d -h -6 -f -a -i -o -x -y -z -g -r -n] <interface>
	  
	Options:
	    -d, --debug                    ... enable scapy verbose output
	    -h, --help                     <-- you are here :)
	    
	    -6, --ipv6                     ... DHCPv6 (off, DHCPv4 by default)
	    
	    -f, --fuzz                     ... randomly fuzz packets (off)
	    
	    -a, --show-arp                 ... detect/print arp who_has (off)
	    -i, --show-icmp                ... detect/print icmps requests (off)
	    -o, --show-options             ... print lease infos (off)
	    
	    -g, --neighbors-attack-garp    ... knock off network segment using gratious arps (off)
	    -r, --neighbors-attack-release ... release all neighbor ips (off)
	    -n, --neighbors-scan-arp       ... arp neighbor scan (off)
	    
	    -x, --timeout-threads          ... thread spawn timer (0.4)
	    -y, --timeout-dos              ... DOS timeout (8) (wait time to mass grat.arp)
	    -z, --timeout-dhcprequest       ... dhcp request timeout (2)


EXAMPLE
-------

    ./pig.py eth1
    ./pig.py --show-options eth1
    ./pig.py -x1 --show-options eth1
    
    ./pig.py -6 eth1
    ./pig.py -6 --fuzz eth1
    
    ./pig.py --neighbors-scan-arp -r -g --show-options eth1


ACTION-SHOTS
-------------

* IPv4
	x@y:/src/DHCPig# python pig.py eth2
	WARNING: No route found for IPv6 destination :: (no default route?)
	[INFO] - using interface eth2
	[--->] DHCP_Discover
	[--->] DHCP_Discover
	[--->] DHCP_Discover
	[<---] DHCP_Offer   00:0c:29:4f:0e:35 0.0.0.0 IP: 172.20.168.82 for MAC=[00:0c:29:59:65:70]
	[--->] DHCP_Request 172.20.168.82
	[--->] DHCP_Discover
	[<---] DHCP_Offer   00:0c:29:4f:0e:35 0.0.0.0 IP: 172.20.168.83 for MAC=[00:0c:29:65:f1:66]
	[--->] DHCP_Request 172.20.168.83
	[--->] DHCP_Discover
	[<---] DHCP_Offer   00:0c:29:4f:0e:35 0.0.0.0 IP: 172.20.168.84 for MAC=[00:0c:29:61:58:26]
	[--->] DHCP_Request 172.20.168.84
	......

* IPv6
	x@y:/src/DHCPig# python pig.py -6 eth2
	WARNING: No route found for IPv6 destination :: (no default route?)
	[INFO] - using interface eth2
	[--->] v6_DHCP_Discover [cid:'\x00\x01\x00\x01P\xb4\xd2\x0b\x00\x0c)Y\xe3\xf1']
	[--->] v6_DHCP_Discover [cid:'\x00\x01\x00\x01P\xb4\xd2\x0c\x00\x0c)A\xcd\xe9']
	[--->] v6_DHCP_Discover [cid:'\x00\x01\x00\x01P\xb4\xd2\x0c\x00\x0c)L\x024']
	[--->] v6_DHCP_Discover [cid:'\x00\x01\x00\x01P\xb4\xd2\r\x00\x0c)\x1c\x1a\xcf']
	[--->] v6_DHCP_Discover [cid:'\x00\x01\x00\x01P\xb4\xd2\r\x00\x0c)s\xdcY']
	[  ? ]          waiting for first DHCP Server response
	[--->] v6_DHCP_Discover [cid:'\x00\x01\x00\x01P\xb4\xd2\r\x00\x0c)~)}']
	[--->] v6_DHCP_Discover [cid:'\x00\x01\x00\x01P\xb4\xd2\x0e\x00\x0c)G\x0f9']



DEFENSE
-------

most common approach to defending DHCP exhaustion is via access layer switching or wireless controllers.  

In cisco switching simplest option is to enable DHCP snooping.  Snooping will defend against pool exhaustion,
IP hijacking, and DHCP sever spoofing  all of which are used in DHCPig.   Based on examined traffic, DHCP 
snooping will create a mapping table from IP to mac on each port.  User access ports are then restricted to only 
the given IP.  Any DHCP server messages originating from untrusted ports are filtered.


enable the following to defend against pool exhaustion, IP hijacking, and DHCP sever spoofing:

* enable snooping 

    `ip dhcp snooping`
    
* specify which port your DHCP is associated with.  Most likely this is your uplink.  Doing the following will 
limit DHCP server responses to only the specified port, so use after testing in lab environment.

    `int fa0/1`  (or correct interface)

    `ip dhcp snooping trust`

* show status

    `show ip dhcp snopping`

    `show ip dhcp snopping binding`


* additional info:
http://www.cisco.com/en/US/docs/switches/lan/catalyst4500/12.1/12ew/configuration/guide/dhcp.pdf



LICENSE:
--------
These scripts are all released under the GPL v2 or later.  For a full description of the licence, 
please visit [http://www.gnu.org/licenses/gpl.txt](http://www.gnu.org/licenses/gpl.txt)

DISCLAIMER:
---------
All information and software available on this site are for educational purposes only. The author 
is no way responsible for any misuse of the information.  


