import yaml
import requests
import json
import logging
from scapy.all import *
from threading import Thread, Event
from time import sleep

# Reading configuration
print('[core]: Reading config file...')
with open('config.yml', 'r') as fconf:
    config = yaml.load(fconf)
    webhook = config['slack']['webhook']
    for uri in webhook:
        webhookUri = uri
    sniffFilter = config['sniffingconf']['filter']
    for stanza in sniffFilter:
        sFilter = stanza
    localIp = config['sniffingconf']['localaddr']
    targetNets = config['destnets']['cidraddr']
    logLocation = config['logging']['relativepath']
    for stanza in logLocation:
        if stanza is not None:
            log = stanza
fconf.close()

# Initializing logging
logging.basicConfig(format='%(asctime)s %(message)s', filename=log, level=logging.WARNING)

# Prepping Sniffer class
class Sniffer(Thread):
    def  __init__(self, interface="eth0", filter="udp", webhook=""):
        super().__init__()

        self.daemon = True
        self.filter = filter
        self.socket = None
        self.interface = interface
        self.webhook = webhook
        self.stop_sniffer = Event()

    def run(self):
        self.socket = conf.L2listen(
            type=ETH_P_ALL,
            iface=self.interface,
            filter=self.filter
        )

        sniff(
            opened_socket=self.socket,
            prn=self.print_packet,
            stop_filter=self.should_stop_sniffer
        )

    def join(self, timeout=None):
        self.stop_sniffer.set()
        super().join(timeout)

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

    def print_packet(self, packet):
        ip_layer = packet.getlayer(IP)
        print("[sniffer]: Packet received: {src} -> {dst}".format(src=ip_layer.src, dst=ip_layer.dst))
        if packet[UDP].dport == 137:
            post = {'text': "NBNS poisoning attempt: {data}".format(data=packet[UDP].summary())}
        elif packet[UDP].dport == 5355:
            post = {'text': "LLMNR poisoning attempt: {data}".format(data=packet[UDP].summary())}
        else:
            post = {'text': "Some unrecognized reply: {data}".format(data=packet[UDP].summary())}
        if self.webhook:
            requests.post(self.webhook, data=json.dumps(post), headers={'Content-Type': 'application/json'})
        logging.warning(post)

# Main process
print('[core]: Initializing Sniffer...')
sniffer = Sniffer(filter=sFilter, webhook=webhookUri)
sniffer.start()
sleep(10)
print('[core]: Starting sending phish packets...')
for net in targetNets:
    print('[asker]: sending to: {dst}'.format(dst=net))
    queryid = random.getrandbits(16)
    send(IP(dst=net)/UDP(sport=137, dport="netbios_ns")/NBNSQueryRequest(SUFFIX="file server service",QUESTION_NAME="corpsoft-1", QUESTION_TYPE="NB"))
    send(IP(dst=net)/UDP(sport=5355, dport=5355)/LLMNRQuery(id=queryid, qr=0, opcode=0, qdcount=1, qd=DNSQR(qname='shareddocs',qtype='A')))

# Running non-stop, waiting for keyboard interrupt
try:
    while True:
        sleep(100)
except KeyboardInterrupt:
    print("[core]: Stopping Sniffer...")
    sniffer.join(2.0)

    if sniffer.isAlive():
        sniffer.socket.close()
