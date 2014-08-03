#!/usr/bin/env python
# -*- coding: utf-8 -*-
# (c) 2014, stf - AGPLv3+

# start like:
# airmon-ng start wlan0
# ifconfig wlan0 down
# ./wprox.py

from scapy.all import sniff, Dot11
# pip install git+https://github.com/pingflood/pythonwifi.git
from pythonwifi.iwlibs import Wireless, Iwrange
from netaddr import OUI
import time, traceback, sys
from itertools import count, groupby

chanmap = {"2412": 1, "2417": 2, "2422": 3, "2427": 4, "2432": 5,
           "2437": 6, "2442": 7, "2447": 8, "2452": 9, "2457": 10,
           "2462": 11, "2467": 12, "2472": 13, "2484": 14, "4915": 183,
           "4920": 184, "4925": 185, "4935": 187, "4940": 188, "4945": 189,
           "4960": 192, "4980": 196, "5035": 7, "5040": 8, "5045": 9,
           #"5055": 11, "5060": 12,
           "5080": 16, "5170": 34, "5180": 36,
           "5190": 38, "5200": 40, "5210": 42, "5220": 44, "5230": 46,
           "5240": 48, "5260": 52, "5280": 56, "5300": 60, "5320": 64,
           "5500": 100, "5520": 104, "5540": 108, "5560": 112, "5580": 116,
           "5600": 120, "5620": 124, "5640": 128, "5660": 132, "5680": 136,
           "5700": 140, "5745": 149, "5765": 153, "5785": 157, "5805": 161,
           "5825": 165}
freqmap = { v: k for k, v in chanmap.items()}

def chan2freq(chan):
    return "%.3fGHz" % (float(freqmap[chan])/1000)

def bar(val, mx, size):
    bars=u"▏▎▍▌▋▊▉█"
    width=(val%(mx/size))*(float(len(bars))/(mx/size))
    return (u"█" * int(val/(mx/size))) + (bars[int(width)])

def tointrange(data):
    return ",".join("-".join(map(str,(g[0],g[-1])[:len(g)]))
                   for g in (list(x)
                             for _,x in groupby(data, lambda x,c=count(): next(c)-x)))

class ChanSniffer():
    def __init__(self, interface, freq = "2.424GHz" , timeout = 15, verbose=True):
        self.interface = interface
        self.verbose = verbose
        self.freq = freq
        self.peers = {}
        self.lastseen = None
        self.lastshown = None
        self.end_sniffing = False
        self.timeout = timeout

    def run(self, freq = None, timeout = None):
        self.end_sniffing = False
        if freq:
            self.freq = freq
        if timeout:
            self.timeout = timeout

        if self.timeout:
            self.lastseen = time.time()
        try:
            Wireless(self.interface).setFrequency(self.freq)
        except IOError:
            print >>sys.stderr, traceback.format_exc()
            print >>sys.stderr, "meh"
            return
        if self.verbose:
            self.lastshown = time.time()
            print >>sys.stderr, "listening on %s chan: %s (%s)" % (self.interface, chanmap[self.freq[0]+self.freq[2:5]], self.freq)
        while self.lastseen and self.timeout and self.lastseen+self.timeout>time.time() and not self.end_sniffing:
            sniff(iface=self.interface, prn=self.handler, timeout=self.timeout, store=0, stop_filter=self.stop_sniffing)
        return self.peers

    def siglevel(self, packet):
        return -(256-ord(packet.notdecoded[-4:-3]))

    def addseen(self, p):
        try:
            self.peers[p.addr2]['seen'].append({'chan': chanmap[self.freq[0]+self.freq[2:5]],
                                            'ts': time.time(),
                                            'rssi': self.siglevel(p) if self.siglevel(p)!=-256 else -100})
        except:
            self.peers[p.addr2]['seen']= [{'chan': chanmap[self.freq[0]+self.freq[2:5]],
                                       'ts': time.time(),
                                       'rssi': self.siglevel(p) if self.siglevel(p)!=-256 else -100}]

    def newdev(self, t, p):
        self.peers[p.addr2] = {'type': t,
                               'ssids': [repr(p.info)],
                               'seen': [{'chan': chanmap[self.freq[0]+self.freq[2:5]],
                                         'ts': time.time(),
                                         'rssi': self.siglevel(p) if self.siglevel(p)!=-256 else -100}]}
        if self.timeout: self.lastseen=time.time()

    def adddev(self, p):
        try:
            self.peers[p.addr2]['ssids'].append(repr(p.info))
        except KeyError:
            self.peers[p.addr2]['ssids']=[repr(p.info)]

        self.addseen(p)
        if self.timeout: self.lastseen=time.time()


    def newpeer(self, peer, other, t, p):
        self.peers[peer] = {'type': t,
                            'peers': other,
                            'seen': [{'chan': chanmap[self.freq[0]+self.freq[2:5]],
                                      'ts': time.time(),
                                      'rssi': self.siglevel(p) if self.siglevel(p)!=-256 else -100}]}
        if self.timeout: self.lastseen=time.time()

    def addpeer(self, dev, peer, p):
        try:
            self.peers[dev]['peers'].append(peer)
        except KeyError:
            self.peers[dev]['peers']=[peer]

        self.addseen(p)
        if self.timeout: self.lastseen=time.time()

    def guesstype(self, other, p):
        t = self.peers.get(other,{}).get('type')
        if t:
            if t == 'ap':
                t = 'client'
            else: t = 'ap'
        return t

    def fixtype(self, t, p):
        self.peers[p.addr2]['type']=t #'client'
        for dev in self.peers[p.addr2]['peers']:
            if self.peers[dev]['type'] not in ['ap' if t == 'client' else 'client', None]:
                print >>sys.stderr, "[pff] type already set", dev, self.peers[dev]['type']
            self.peers[dev]['type']='ap' if t == 'client' else 'client'

    def handler(self, p):
        if p.haslayer(Dot11):
            if p.type == 0:
                if p.subtype in (0,2,4):
                    if p.addr2 not in self.peers:
                        #print "[new] %s %s\t%s" % (p.addr2.upper(),
                        #                           repr(p.info),
                        #                           OUI(p.addr2[:8].replace(':','-')).registration().org)
                        self.newdev('client', p)
                    elif repr(p.info) not in self.peers[p.addr2].get('ssids',[]):
                        #print "[add] %s %s\t%s" % (p.addr2.upper(),
                        #                                    repr(p.info),
                        #                                    OUI(p.addr2[:8].replace(':','-')).registration().org)
                        if not self.peers[p.addr2]['type']:
                            self.fixtype('client',p)
                        self.adddev(p)
                    else:
                        self.addseen(p)
                elif p.subtype == 8: # beacon
                    if p.addr2 not in self.peers:
                        #print "{new} %s %s\t%s" % (p.addr2.upper(),
                        #                           repr(p.info),
                        #                           OUI(p.addr2[:8].replace(':','-')).registration().org)
                        self.newdev('ap', p)
                    elif repr(p.info) not in self.peers[p.addr2].get('ssids',[]):
                        #print "{add} %s %s\t%s" % (p.addr2.upper(),
                        #                           repr(p.info),
                        #                           OUI(p.addr2[:8].replace(':','-')).registration().org)
                        if not self.peers[p.addr2]['type']:
                            self.fixtype('ap',p)
                        self.adddev(p)
                    else:
                        self.addseen(p)
            if p.type == 2:
                if p.addr2 not in self.peers or (p.addr1 not in self.peers and p.addr1.lower() != 'ff:ff:ff:ff:ff:ff'):
                    if p.addr2 not in self.peers:
                        t = self.guesstype(p.addr1, p)
                        self.newpeer(p.addr2, [p.addr1] if p.addr1.lower() != 'ff:ff:ff:ff:ff:ff' else [], t, p)
                    elif p.addr1 not in self.peers[p.addr2].get('peers',[]):
                        self.addpeer(p.addr2, p.addr1, p)
                    elif self.peers[p.addr2]['seen'][-1]['ts']+0.5<time.time():
                        self.addseen(p)
                    if p.addr1 not in self.peers and p.addr1.lower() != 'ff:ff:ff:ff:ff:ff':
                        t = self.guesstype(p.addr2, p)
                        self.newpeer(p.addr1, [p.addr2], t, p)
                    elif p.addr1.lower() != 'ff:ff:ff:ff:ff:ff' and p.addr2 not in self.peers[p.addr1].get('peers',[]):
                        self.addpeer(p.addr1, p.addr2, p)
                    #print "<con> %s %s <-> %s %s" % (p.addr2, self.peers[p.addr2], p.addr1, self.peers[p.addr1])

                    # deauth to see roles?
                    #sendp(RadioTap()/Dot11(type=0,subtype=12,addr1=p.addr2,addr2=p.addr3,addr3=p.addr3)/Dot11Deauth())
                else:
                    self.addseen(p)

            if self.lastseen and self.timeout and self.lastseen+self.timeout<time.time():
                self.end_sniffing=True
            if self.verbose and self.lastshown+2<time.time():
                print >>sys.stderr, '-' * 133
                print >>sys.stderr, self.display()
                print >>sys.stderr, "listening on %s chan: %s (%s)" % (self.interface, chanmap[self.freq[0]+self.freq[2:5]], self.freq)
                self.lastshown = time.time()

    def stop_sniffing(self, pkt):
        return self.end_sniffing

    def rfstats(self, data):
        count = len(data)
        mx = max(x['rssi'] for x in data)
        mn = min(x['rssi'] for x in data)
        avg = sum(x['rssi'] for x in data) / count
        sprd = mx - mn
        chan = sorted(set(x['chan'] for x in data))
        return u"[%-18s] %4s %4s %4s %4s %2s [%-5s]" % (tointrange(chan),
                                                        count,
                                                        mx,
                                                        mn,
                                                        avg,
                                                        sprd,
                                                        bar(100+avg, 70, 5))

    def print_client(self, k, v):
        if v['type']!='client':
            return
        try:
            vendor = OUI(k[:8].replace(':','-')).registration().org
        except:
            vendor = ''
        if len(vendor)>20:
            vendor = "%s..." % vendor[:20]
        return "%s %-23s %s %s" % (k,
                                      vendor,
                                      self.rfstats(v['seen']),
                                      ', '.join(v.get('ssids',[])))

    def display(self):
        shown = set()
        res=["typ AP SSID*                      MAC               vendor                  channels              cnt  max  min  avg  sp rssi   attempts"]
        for k, v in sorted(self.peers.items(),key=lambda (k,v): len(v.get('peers',[])), reverse=True):
            if v['type']!='ap': continue
            try:
                vendor = OUI(k[:8].replace(':','-')).registration().org[:20]
            except:
                vendor = ''
            if len(vendor)>20:
                vendor = "%s..." % vendor[:20]
            res.append("AP %-30s %s %-23s %s" % (', '.join(v.get('ssids',[])), k, vendor, self.rfstats(v['seen'])))
            for client in sorted(v.get('peers',[]), lambda _,v1: len(self.peers[v1].get('ssids',[])) ,reverse=True):
                res.append("   %-30s %s" % (', '.join(v.get('ssids',[])), self.print_client(client, self.peers[client])))
                shown.add(client)

        for k, v in self.peers.items():
            if v['type']!='client' or k in shown: continue
            res.append("CL %s %s" % (' '*30, self.print_client(k,v)))

        for k, v in self.peers.items():
            if v['type']!='unknown': continue
            res.append("NA %s <-> %s" % (k, v.get('peers')))
        return '\n'.join(res)

if __name__ == "__main__":
    iwrange = Iwrange(sys.argv[1])
    if iwrange.errorflag:
        print (iwrange.errorflag, iwrange.error)
        sys.exit(1)

    cs=ChanSniffer(sys.argv[1])
    #cs.run(freq=chan2freq(11),timeout=3)
    for freq in sorted(iwrange.frequencies):
        #if freq > 3000000000: continue
        cs.run(freq="%.3fGHz" % (freq/1000000000.0),timeout=23)
    print cs.display().encode('utf8')
