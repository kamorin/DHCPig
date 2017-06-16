% DHCPIG(1) DHCPig Man Page
% Philippe Thierry
% June 2017
# NAME
dhcpig - DHCP exhaustion script using scapy network library

# SYNOPSIS
**dhcpig [options] <interface>**
**dhcpig -h|--help**

# DESCRIPTION

DHCPig initiates an advanced DHCP exhaustion attack. It will consume all IPs
on the LAN, stop new users from obtaining IPs, release any IPs in use, then
for good measure send gratuitous ARP and knock all windows hosts offline.

When executed the script will perform the following actions:

   Grab your Neighbors IPs before they do
   Listen for DHCP Requests from other clients if offer detected, respond with
   request for that offer.

   Request all available IP addresses in Zone
   Loop and Send DHCP Requests all from different hosts & MAC addresses

   Find your Neighbors MAC & IP and release their IP from DHCP server
   ARP for all neighbors on that LAN, then send DHCPReleases to server

   Finally the script will then wait for DHCP exhaustion, (that is no received
DHCP OFFERs for 10 seconds) and then

   Knock all Windows systems offline
   gratuitous ARP the LAN, and since no additional DHCP addresses are available
these windows systems should stay offline. Linux systems will not give up IP
even when another system on LAN is detected with same IP.

# OPTIONS:

The options of DHCPig are the following. For each option, the default value or
default behavior is set between parenthesis.

**-h**, **--help**
  show this help message and exit

**-v, --verbosity**
  Set verbosity level. Can be set to:
    0 ... no         (3)
    1 ... minimal
   10 ... default
   99 ... debug
	                                       
**-6, --ipv6**
  DHCPv6 (off, DHCPv4 by default)

**-1, --v6-rapid-commit**
  enable RapidCommit (2way ip assignment instead of 4way) (off)
	    
**-s, --client-src**
  a list of client macs 00:11:22:33:44:55,00:11:22:33:44:56 (Default: <random>)

**-O, --request-options**
  option-codes to request e.g. 21,22,23 or 12,14-19,23 (Default: 0-80)
	    
**-f, --fuzz**
  randomly fuzz packets (off)
	
**-t, --threads**
  number of sending threads (1)
	    
**-a, --show-arp**
  detect/print arp who_has (off)

**-i, --show-icmp**
  detect/print icmps requests (off)

**-o, --show-options**
  print lease infos (off)

**-l, --show-lease-confirm**
  detect/print dhcp replies (off)
    
**-g, --neighbors-attack-garp**
  knock off network segment using gratious arps (off)

**-r, --neighbors-attack-release**
  release all neighbor ips (off)

**-n, --neighbors-scan-arp**
  arp neighbor scan (off)
    
**-x, --timeout-threads**
  thread spawn timer (0.4)

**-y, --timeout-dos**
  DOS timeout (8) (wait time to mass grat.arp)

**-z, --timeout-dhcprequest**
  dhcp request timeout (2)
    
**-c, --color**
  enable color output (off)

# HISTORY

June 2017, Man page originally compiled by Philippe Thierry (phil at reseau-libre dot
com)
