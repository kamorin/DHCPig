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


USAGE
-----
DHCP exhaustion attack plus.

Usage:
  pig.py [-d -h] <interface>
        -h                this help display
        -d                enable debug


EXAMPLE
-------
...

./piy.py eth1

...


LICENSE:
--------
These scripts are all released under the GPL v2 or later.  For a full description of the licence, 
please visit [http://www.gnu.org/licenses/gpl.txt](http://www.gnu.org/licenses/gpl.txt)


