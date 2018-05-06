# -*- coding: utf-8 -*-
#!/usr/bin/env python
import pcapy
import dns.message
import datetime
from myevent import myevent
from dateutil import parser

OFFSET = 42
A = 1
AAAA = 28
CNAME = 5

TYPES = {
    A: 'A',
    AAAA: 'AAAA',
    CNAME: 'CNAME'
}

def date(d):
    return datetime.datetime.fromtimestamp(d).strftime("%d/%m/%Y %H:%M:%S.%f")

def get_answers(m):
    for a in m.answer:
        if a.rdtype not in TYPES: continue
        for i in a:
            yield i.to_text().lower(), TYPES[a.rdtype], a.ttl

def get_query(m):
    try :
        query = m.question[0].to_text().split()[0]
    except IndexError:
        return None
    if query.endswith("."):
        query = query[:-1]
    return query.lower()
        
class Statmaker:
    def __init__(self):
        self.ipnames = {}

    def __call__(self, header, data):

        ts, _ =  header.getts()
        try :
            m = dns.message.from_wire(data[OFFSET:])
        except:
            return
        query = get_query(m)
        if not query:
            return

        ipn = self.ipnames

        for answer, type, ttl in get_answers(m):
            tup = (answer, query, type)
            if tup in ipn:
                r = ipn[tup]
                r.update({'last': ts, 'ttl': ttl})
            else:
                ipn[tup]={'first': ts, 'last': ts, 'ttl': ttl}

        
def parse(fn):
    s = Statmaker()
    pcap = pcapy.open_offline(fn)
    pcap.loop(0, s)

    return s

def report(fn):
    s = parse(fn)

    data = s.ipnames.items()
    data.sort()
    
    result = []
    for (answer, query, type), rec in data:
        desc = "Query: <b>" + query + "</b><br>" + "Answer: <b>" + answer + "</b><br>" + "Type: <b>" + type + "</b><br>" + "First time: <b>" + date(rec['first']) + "</b><br>" + "Last time; <b>" + date(rec['last']) + "</b>"
        res = myevent(parser.parse(date(rec['first'])), "network", "DNS", "Not applicable", desc)
        result.append(res)
        #print "%s %s %s %s %s %s\n" % (answer, query, type, rec['ttl'], date(rec['first']),date(rec['last']))

    return result