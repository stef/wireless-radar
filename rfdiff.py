#!/usr/bin/env python
# -*- coding: utf-8 -*-
# (c) 2014, stf - AGPLv3+

# start like:
# ./rfdiff.py newscan oldscan
#
# where newscan and oldscan are the stdouts of different wprox scans

from datetime import datetime
import sys
import netaddr

def getvendor(mac):
    try:
        return "[%s]" % (netaddr.OUI(mac[:8].replace(':','-')).registration().org)
    except netaddr.core.NotRegisteredError:
        return ''

wmeta=[{'name': 'mac', 'out': getvendor},
       {'name': 'essid', 'id': True},
       {'name': 'type'},
       {'name': 'chans', 'ignore': True},
       {'name': 'count', 'threshold': 30},
       {'name': 'avg', 'threshold': 30},
       {'name': 'max', 'threshold': 30},
       {'name': 'min', 'threshold': 30},
       {'name': 'spread', 'ignore': True}, # needs other, can vary 1-2 or even around 50
       {'name': 'attempts'},
      ]

def load(fn):
    res={}
    with open(fn,'r') as fd:
        for line in fd.readlines()[1:]:
            stats=line[77:]
            idx=stats.find(']')
            mac=line[34:51]
            res[mac] = (mac,                                    # mac
                        line[2:32].strip(),                     # essid
                        'CL' if line[:2] == '  ' else line[:2], # type
                        stats[:idx].strip(),                    # chans
                        int(stats[idx+2:idx+6].strip()),        # count
                        int(stats[idx+7:idx+11].strip()),       # max
                        int(stats[idx+12:idx+16].strip()),      # min
                        int(stats[idx+17:idx+21].strip()),      # avg
                        int(stats[idx+22:idx+24].strip()),      # spread
                        stats.decode('utf8')[idx+32:].strip(),  # attempts
                        )
    return res

def wskip(rec):
    return rec[3]>-85

old=load(sys.argv[1])
new=load(sys.argv[2])

# deleted
deleted=set(old.keys()) - set(new.keys())
if deleted:
    rendered = [' '.join([wmeta[i].get('out', str)(old[k][i])
                         for i in xrange(len(wmeta))])
                for k in deleted if not wskip(old[k])]
    if rendered:
        print 'gone\t%s' % '\ngone\t'.join(rendered)

# new
added=set(new.keys()) - set(old.keys())
try:
    if added:
        rendered = [' '.join([wmeta[i].get('out', str)(new[k][i])
                              for i in xrange(len(wmeta))])
                    for k in added if not wskip(new[k])]
        if rendered:
            print 'new\t%s' % '\nnew\t'.join(rendered)
except:
    import code; code.interact(local=locals());


# rest
rest=set(new.keys()) & set(old.keys())
if rest:
    for k in rest:
        diffs=[]
        id=[]
        for i, (oldelem, newelem) in enumerate(zip(old[k],new[k])):
            if 'id' in wmeta[i]:
                id.append(newelem)
            if oldelem==newelem: continue
            if 'ignore' in wmeta[i] and wmeta[i]['ignore']:
                continue
            if 'threshold' in wmeta[i]:
                o=float(oldelem)
                n=float(newelem)
                if min((o,n))/max((o,n)) < (wmeta[i]['threshold']+100)/100.0:
                    continue
            diffs.append((wmeta[i]['name'],oldelem,newelem))
        if diffs:
            print '/'.join(x for x in id if x) or k, getvendor(k), "\n\t%s" % '\n\t'.join("%s: %s \t -> \t%s" % data for data in  diffs)
