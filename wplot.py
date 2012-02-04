#!/usr/bin/env python

from pylab import *
from pythonwifi.iwlibs import Wireless

ion()
figure()
ax = subplot(111, autoscale_on=True)
w=Wireless('wlan0')

i=0
APs={}
while True:
    updated=[]
    for h in w.scan():
        try:
            APs[h.bssid][1].append(h.quality.getSignallevel())
        except:
            try:
                name=h.essid.decode('utf8')
            except:
                name=h.bssid
            q=[None] * i + [h.quality.getSignallevel()]
            l,=plot(arange(0,i+1,1),q, label=name)
            APs[h.bssid]=(h.essid, q, l)
        updated.append(h.bssid)
    for k, v in APs.items():
        if k in updated: continue
        v[1].append(None)
    if i%5==1:
        for bssid, (essid, q, line) in sorted(APs.items()):
            line.set_ydata(q)
            line.set_xdata(arange(0,i+1,1))
        legend(loc='upper left', labelspacing=0.1, prop={'size': 7})
        ax.relim()
        ax.autoscale_view()
        draw()
    i+=1
