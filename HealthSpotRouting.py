from scapy.all import *
import subprocess
import re

#Any script running this needs to be run with sudo in order for
#scapy to work

class HealthSpotRouting:
	
	def __init__(self, mac_address="b8:27:eb:85:ab:76", gateway_ip="192.168.0.1/24"):
		self.mac = mac_address
		self.gateway = gateway_ip

	
	def get_gateway_ip(self):
		ipget = subprocess.Popen(["ip", "route"], stdout=subprocess.PIPE)
		output, _ = ipget.communicate()
		lines = output.decode()
		for line in lines.split('\n'):
			if 'default' in line:
				gateway = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line)
				return gateway.group(0) + "/24"


	def get_pi_ip(self):
		self.mac = "b8:27:eb:85:ab:76"
		self.gateway = self.get_gateway_ip()
		searchstr = "Searching for mac address: {0}=>using gateway: {1}".format(self.mac, self.gateway)
		print(searchstr)
		ans, unans = srp(Ether(dst=self.mac)/ARP(pdst=self.gateway), timeout=2)
		ans.summary()
		return ans[0][0].pdst


