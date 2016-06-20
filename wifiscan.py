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
     
    if pkt.addr2 =="00:08:22:" : pkt.addr2 = ""			# 
    if pkt.addr2 =="70:f1:a1:" : pkt.addr2 = ""			# Mini
    if pkt.addr2 =="00:1f:3a:" : pkt.addr2 = ""         # Portatil 
    
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
