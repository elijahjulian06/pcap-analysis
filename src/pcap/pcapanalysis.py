
"""
created on Thu Jan 12 07:31:55 2023

@author: ejuli_000
"""

from scapy.all import *

def open_pcap_file(file_name):
    packet_file = rdpcap(file_name)
    print(len(packet_file))

from scapy.utils import RawPcapReader 
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

def IPv4only(file_name): 
    count = 0
    input_packet = PcapReader(file_name)
    output_packet = PcapWriter('output_file.pcap', append=True)
    
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        ether_pkt = Ether(pkt_data)
        if 'type' in ether_pkt.fields:
            if ether_pkt.type == 0x0800: 
                time.sleep(1)
                packet = input_packet.read_packet()
                output_packet.write(packet)
                count += 1
                print(count)


IPv4only('example-01.pcap')

    
