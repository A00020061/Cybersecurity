# This is imported from the 'collection' module. It's used to create a dictionary with default
#values for keys that have not been set yet.
from collections import defaultdict
import time

#'os' and 'sys' modules are used for interacting with the operating system.
import os, sys
#'sniff' is used for capturing packets, and 'IP' represents the IP packet in Scapy.
from scapy.all import sniff, IP

packet_count = defaultdict(int)
start_time= [time.time()]
blocked_ips = set()

threshold = 40

def packet_callback(packet):
#extract the src_ip address
    src_ip = packet[IP].src
#increments the count of packets received from each source IP address
    packet_count[src_ip] = +1
    current_time = time.time()
#It calculates the time interval since the last action was taken
    time_interval = current_time - start_time[0]
#if time intervel is greater than or equal to 1 second, it checks the packet rate for each 
    #IP address.
    if time_interval >=1:
        for ip, count in packet_count.items():
            packet_rate = count/time_interval
#If the packet rate exceeds the threshold and the IP address is not already blocked, it blocks
#the IP address using 'os.system'.
            if packet_rate > threshold and ip not in blocked_ips:
                print(f'blocking IP: {ip}, packet_rate:, {packet_rate}')
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                blocked_ips.add(ip)
#it clear the packet count and updates the start time.
        packet_count.clear()
        start_time[0]= current_time

if __name__ == '__main__':
    if os.geteuid() != 0:
        sys.exit(1)

    print('monitoring network traffic.....')
    sniff(filter='ip', prn=packet_callback)