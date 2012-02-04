#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pythonwifi.iwlibs import Wireless
from datetime import datetime
from launcher import RocketManager
from functools import partial
from operator import itemgetter
import sys, os, time, signal

interface='wlan1'

LEFT=3
RIGHT=2
UP=1
DOWN=0

HMAX=3400
VMAX=280

blocks = u' ▁▂▃▄▅▆▇██'

class Scanner():
    def __init__(self, wireless, x=0, y=0, rm=True):
        self.w=Wireless(wireless)
        if rm: self.init_launcher()
        self.x=x
        self.y=y
        self.aps={}

    def init_launcher(self):
        self.rm=RocketManager()
        self.rm.acquire_devices()

    def step(self,dir,steps=1):
        for _ in xrange(steps):
            self.rm.launchers[0].start_movement(dir)
            self.rm.launchers[0].stop_movement()
            if dir==RIGHT:
                self.x-=1
            elif dir==LEFT:
                self.x+=1
            elif dir==UP:
                self.y+=1
            elif dir==DOWN:
                self.y-=1

    def home(self):
        print "press c-c when in home position"
        while True:
            print s.x
            try:
                s.step(RIGHT,steps=200)
            except KeyboardInterrupt:
                self.rm.launchers[0].stop_movement()
                sys.exit(0)

    def scan(self):
        res=[]
        for h in self.w.scan():
            try:
                name=h.essid.decode('utf8')
            except:
                name=h.bssid
            res.append((datetime.now().isoformat(), h.bssid, h.quality.getSignallevel(), name.strip()))
        return res

    def store(self, x, y, date, bssid, rssi, name):
        try:
            self.aps[bssid]['rssi'].append((date, int(rssi), int(x), int(y)))
        except:
            self.aps[bssid]={'name': name.strip(),
                             'rssi': [(date, int(rssi), int(x), int(y))]}

    def fasth(self, c=1, steps=10, cb=None, sweeps=1):
        res=[]
        dirs=[LEFT, RIGHT]
        for i in xrange(sweeps):
            dir=dirs[i%2]
            while 0<=self.x<=HMAX:
                # scan c times
                scan=[(self.x, self.y, date, bssid, rssi, name)
                      for _ in xrange(c)
                      for date, bssid, rssi, name in self.scan()]
                # handle callback
                if cb: scan=cb(scan)
                for ap in scan:
                    # print all scan records
                    print ' '.join([unicode(f) for f in ap])
                    self.store(*ap)

                res.extend(scan)
                self.step(dir,steps)
            if dir==LEFT: self.x=HMAX
            else: self.x=0
        return res

    def apRSSI(self, target, batch):
        # x, y, date, bssid, rssi, name
        data=[item[4] for item in batch if item[3]==target]
        if data:
            rssi=sum(data)/len(data)
            print >>sys.stderr, self.x, rssi, '#'*(rssi+128)
        else:
            print >>sys.stderr, self.x
        return batch

    def stats(self):
        # do some stats on the seen APs
        stats=sorted([(sum([int(rssi) for _, rssi, _, _ in v['rssi'] if rssi!='-256'])/len(v['rssi']),
                       max([int(rssi) for _, rssi, _, _ in v['rssi'] if rssi!='-256']),
                       min([int(rssi) for _, rssi, _, _ in v['rssi'] if rssi!='-256']),
                       max([int(rssi) for _, rssi, _, _ in v['rssi'] if rssi!='-256'])-min([int(rssi) for _, rssi, _, _ in v['rssi'] if rssi!='-256']),
                       key,
                       v['name'])
                      for key, v in self.aps.items()],
                     reverse=True)
        print >>sys.stderr, "avg mx mn sprd key name"
        for avg, mx, mn, sprd, key, name in stats:
            print >>sys.stderr, key, avg, mx, mn, sprd, self.aps[key]['name']

        for ap in s.directions():
            radar=[[0,0] for _ in xrange(20)]
            for item in sorted(s.aps[ap[0]]['rssi'],key=itemgetter(2)):
                radar[int(item[2]/((HMAX+1.0)/20))][0]+=item[1]
                radar[int(item[2]/((HMAX+1.0)/20))][1]+=1
            tmp=[x[0]/x[1] if x[1] else None for x in radar]
            #if len([x for x in tmp if x])>10:
            #    print "|%s| %4s %3s %s %s %s %s" % (' '*20, ap[4], ap[5], ap[2][:19], ap[0], ap[3], ap[1])
            #else:
            #    tmp=[y or min([x for x in tmp if x])-((max([x for x in tmp if x])-min([x for x in tmp if x]))/8)-1 for y in tmp]
            #    print "|%s| %4s %3s %s %s %s %s" % (s.spark(tmp).encode('utf8'), ap[4], ap[5], ap[2][:19], ap[0], ap[3], ap[1])
            tmp=[y or min([x for x in tmp if x])-((max([x for x in tmp if x])-min([x for x in tmp if x]))/8)-1 for y in tmp]
            print "|%s| %4s %3s %s %s %s %s" % (s.spark(tmp).encode('utf8'), ap[4], ap[5], ap[2][:19], ap[0], ap[3], ap[1])

    def load(self,file):
        for line in file.readlines():
            try:
                self.store(*line.split(' ',5))
            except TypeError:
                pass

    def directions(self):
        return sorted([(ap, data['name'])+max(data['rssi'], key=itemgetter(1))
                       for ap, data in self.aps.items()],
                      key=itemgetter(4))

    def spark(self, data):
        line = ''
        lo = float(min(data))
        hi = float(max(data))
        incr = (hi - lo)/9 or 1
        for n in data:
            if n:
                line += blocks[int((float(n) - lo)/incr)]
            else:
                line += ' '
        return line

if __name__ == "__main__":
    if len(sys.argv)>1:
        if sys.argv[1]=='reset':
            s=Scanner(interface)
            s.home()
        elif sys.argv[1]=='load':
            s=Scanner(interface,rm=False)
            s.load(sys.stdin)
            s.stats()
        else:
            # show rssi graph of AP
            s=Scanner(interface)
            cb=partial(s.apRSSI,sys.argv[1])
            s.fasth(c=5, steps=100, cb=cb, sweeps=2)
    else:
        s=Scanner(interface)
        s.fasth(c=5, steps=100, sweeps=2)

