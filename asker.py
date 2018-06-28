import sys
import yaml
import requests
import json
import logging
from scapy.all import *
from threading import Thread, Event
from time import sleep
from smb.SMBConnection import SMBConnection

# Reading configuration
print('[core]: Reading config file...')
try:
    with open('config.yml', 'r') as fconf:
        config = yaml.load(fconf)
        interval = config['phishpackets']['interval']
        nbns_query = config['phishpackets']['NBNSquery']
        llmnr_query = config['phishpackets']['LLMNRquery']
        user = config['phishcredentials']['user']
        passwd = config['phishcredentials']['password']
        pc_name = config['phishcredentials']['workstation']
        pc_domain = config['phishcredentials']['domain']
        target_nets = config['phishpackets']['destnets']
        sniff_filter = config['sniffingconf']['filter']
        local_ip = config['sniffingconf']['localaddr']
        webhook = config['webhook']
        log = config['logfile']
except:
    print('Cannot parse the configuration file: {info}'.format(info=sys.exc_info()[0]))
    raise

# Initializing logging
try:
    logging.basicConfig(format='%(asctime)s %(message)s', filename=log, level=logging.WARNING)
except PermissionError as perr:
    print('Cannot configure logging, check you permissions: {info}'.format(info=perr))
    raise

# Prepping Sniffer class
class Sniffer(Thread):
    def  __init__(self, interface="eth0", filter="udp", smb_user="", smb_client_name="", smb_srv_name="", smb_srv_ip="", smb_domain="", smb_pass="", webhook=""):
        super().__init__()

        self.daemon = True
        self.filter = filter
        self.socket = None
        self.interface = interface
        self.smbuser = smb_user
        self.smbcliname = smb_client_name
        self.smbsrvname = smb_srv_name
        self.smbsrvip = smb_srv_ip
        self.smbdomain = smb_domain
        self.smbpass = smb_pass
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
            # If SMB user option is specified in the config, let's try to sent phishing hashes by accessing the provided file server address
            if self.smbuser:
                print('[sniffer]: Trying to send phising hashes to file server: {0}'.format(packet[3].an.rdata))
                try:
                    conn = SMBConnection(self.smbuser, self.smbpass, self.smbcliname, self.smbsrvname, domain=self.smbdomain, use_ntlm_v2=True, is_direct_tcp=True)
                    conn.connect(packet[3].an.rdata, 445)
                except:
                    print('[sniffer]: Something went wrong. It does not necessarily mean that hashes were not sent.')
        else:
            post = {'text': "Some unrecognized reply: {data}".format(data=packet[UDP].summary())}
        if self.webhook:
            requests.post(self.webhook, data=json.dumps(post), headers={'Content-Type': 'application/json'})
        logging.warning(post)

# Main process
print('[core]: Initializing Sniffer...')
sniffer = Sniffer(filter=sniff_filter, webhook=webhook, smb_user=user, smb_client_name=pc_name, smb_srv_name=nbns_query, smb_domain=pc_domain, smb_pass=passwd)
sniffer.start()
sleep(10)
# Will be sending phishing packets until Ctrl-C
try:
    while True:
        print('[core]: Starting sending phish packets...')
        for net in target_nets:
            print('[asker]: sending to: {dst}'.format(dst=net))
            query_id = random.getrandbits(16)
            try:
                send(IP(dst=net)/UDP(sport=137, dport=137)/NBNSQueryRequest(SUFFIX="file server service", QUESTION_NAME=nbns_query, QUESTION_TYPE='NB'))
                sleep(15)
                send(IP(dst=net)/UDP(sport=5355, dport=5355)/LLMNRQuery(id=query_id, qr=0, opcode=0, qdcount=1, qd=DNSQR(qname=llmnr_query,qtype='A')))
            except PermissionError as perr:
                print('Cannot send packet, check you permissions: {info}'.format(info=perr))
        # Freeze for the specified interval and start all over again.
        sleep(interval)
except KeyboardInterrupt:
    print("[core]: Stopping Sniffer and Asker...")
    sniffer.join(2.0)
    if sniffer.isAlive():
        sniffer.socket.close()
