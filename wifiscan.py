from scapy.all import *
import time

PROBE_REQUEST_TYPE=0
PROBE_REQUEST_SUBTYPE=4

WHITELIST = ['00:00:00:00:00:00',] # Replace this with your phone's MAC address


def PacketHandler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type==PROBE_REQUEST_TYPE and pkt.subtype == PROBE_REQUEST_SUBTYPE :
        # and ( pkt.addr2.lower() in WHITELIST or pkt.addr2.upper() in WHITELIST):
            PrintPacket(pkt)

def PrintPacket(pkt):
    #print "Probe Request Captured:"
    try:
        extra = pkt.notdecoded
    except:
        extra = None
    if extra!=None:
        signal_strength = -(256-ord(extra[-4:-3]))
    else:
        signal_strength = -100
        print "No signal strength found"
        
    lenssid = len(pkt.getlayer(Dot11ProbeReq).info)
     
    if pkt.addr2 =="00:08:22:d8:96:d4" : pkt.addr2 = ""			# Hisense
    if pkt.addr2 =="70:f1:a1:94:f6:f2" : pkt.addr2 = ""			# Mini
    if pkt.addr2 =="00:1f:3a:10:c6:71" : pkt.addr2 = ""         # Portatil c700
    
    if pkt.addr2 =="50:a7:2b:79:7b:95" : pkt.addr2 = "Abelardo"
    if pkt.addr2 =="24:df:6a:ac:41:bd" : pkt.addr2 = "Liber"
    if pkt.addr2 =="14:d6:4d:76:7a:02" : pkt.addr2 = "Liber o Lalo"
    #if pkt.addr2 =="" : pkt.addr2 = "Pepy"
    #if pkt.addr2 =="" : pkt.addr2 = "Cesar"
    # 7c:91:22:3a:65:fa M.Jose ??
    
    if pkt.addr2 != "" :
        print "> %s SSID: %s RSSi: %d"%(pkt.addr2,pkt.getlayer(Dot11ProbeReq).info,signal_strength),time.strftime("%H:%M:%S")
    
    
def main():
    from datetime import datetime
    #print "[%s] Starting scan"%datetime.now()
    #print "Scanning for:"
    #print "\n".join(mac for mac in WHITELIST)
    sniff(iface=sys.argv[1],prn=PacketHandler,store=0)
    
if __name__=="__main__":
    main()
