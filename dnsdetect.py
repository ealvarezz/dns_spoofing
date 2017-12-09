from scapy.all import *
import netifaces
import timeit
import argparse

# This is to sniff packets in promiscous mode
conf.sniff_promisc=True

tracefile = ''
device = ''
packets = []
bpf_filter = 'udp port 53'
sniff_office = False

# This allows me to get the default network device if not specified
def get_default_device():
    return netifaces.gateways()['default'][netifaces.AF_INET][1]

# The following is parsing the arguments
parser = argparse.ArgumentParser(description='Parsing arguements', add_help=False)
parser.add_argument('-i', help='Specified device', required=False)
parser.add_argument('-r', help='List of hostnames', required=False)
parser.add_argument("expresion", type=str, help="this is a string", nargs='?')
args = vars(parser.parse_args())

# Checking will arguemnts were parsed
try:
    if args['i']:
        device = args['i']
        print "Sepecified interface!"
    else:
        device = get_default_device()
    
    if args['expresion']:
        bpf_filter = args['expresion'] + " and port 53 and udp"
    else:
        bpf_filter = "port 53 and udp"

    if args['r']:
        tracefile = args['r']
        sniff_office = True
    else:
        print "Sniffing on specified interface"
except:
    print "Invalid interface."
    sys.exit(1)

# This basically compares two packets and if anything but the response
# and payload match then that means that there was some sort of attempt
# to spoof a dns request
def malicious_packet(packet1, packet2):

    return packet1[DNSRR].rdata != packet2[DNSRR].rdata \
            and packet1[IP].payload != packet2[IP].payload \
            and packet1[DNS].qd.qname == packet2[DNS].qd.qname \
            and packet1[DNS].id == packet2[DNS].id \
            and packet1[IP].dst == packet2[IP].dst \
            and packet1[IP].dport == packet2[IP].dport \
            and packet1[IP].sport == packet2[IP].sport

# This is going to get a packet and compare it to the packets in cache
# If malicious_packetreturn true that means that there two dns requests
# Were made with different responses
def dns_detect(pkt):

    if pkt.haslayer(DNSRR):
        if len(packets) > 0:
            for packet in packets:
                if malicious_packet(pkt, packet):
                    print "You just got hacked!!!"
        
        if len(packets) > 2500:
            packets.clear();
        else:
            packets.append(pkt)

print "default device: " + device
print "Expression: ", bpf_filter

if(sniff_office):
    sniff(filter=bpf_filter, offline = tracefile, store=0, prn=dns_detect)
else:
    sniff(filter=bpf_filter, iface=device, store=0, prn=dns_detect)
