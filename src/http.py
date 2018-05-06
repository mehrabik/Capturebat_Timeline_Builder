# -*- coding: utf-8 -*-
#!/usr/bin/env python
# Turns a pcap file with http gzip compressed data into plain text, making it
# easier to follow.

import dpkt
import datetime
import socket
import myevent
import dateutil

def date(d):
    return datetime.datetime.fromtimestamp(d).strftime("%d/%m/%Y %H:%M:%S.%f")

def ip_to_str(address):
    return socket.inet_ntop(socket.AF_INET, address)

def tcp_flags(flags):
    ret = ''
    if flags & dpkt.tcp.TH_FIN:
        ret = ret + 'F'
    if flags & dpkt.tcp.TH_SYN:
        ret = ret + 'S'
    if flags & dpkt.tcp.TH_RST:
        ret = ret + 'R'
    if flags & dpkt.tcp.TH_PUSH:
        ret = ret + 'P'
    if flags & dpkt.tcp.TH_ACK:
        ret = ret + 'A'
    if flags & dpkt.tcp.TH_URG:
        ret = ret + 'U'
    if flags & dpkt.tcp.TH_ECE:
        ret = ret + 'E'
    if flags & dpkt.tcp.TH_CWR:
        ret = ret + 'C'

    return ret

def parse_http_stream(stream):
    while len(stream) > 0:
        if stream[:4] == 'HTTP':
            http = dpkt.http.Response(stream)
            print http.status
        else:
            http = dpkt.http.Request(stream)
            print http.method, http.uri
        stream = stream[len(http):]

def parse_pcap_file(filename, includecontent):

    #Prepare output
    result = []    
    
    # Open the pcap file
    f = open(filename, 'rb')
    pcap = dpkt.pcap.Reader(f)
    
    # I need to reassmble the TCP flows before decoding the HTTP
    conn = dict() # Connections with current buffer
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
    
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue
    
        tcp = ip.data
    
        tupl = (ip.src, ip.dst, tcp.sport, tcp.dport)
        #print tupl, tcp_flags(tcp.flags)
    
        # Ensure these are in order! TODO change to a defaultdict
        if tupl in conn:
            conn[ tupl ] = conn[ tupl ] + tcp.data
        else:
            conn[ tupl ] = tcp.data
            syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
            ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0
            if (syn_flag and not ack_flag):
                desc = "Source IP: <b>" + ip_to_str(ip.src) + "</b><br>"
                desc = desc + "Source Port: <b>" + str(tcp.sport)  + "</b><br>"
                desc = desc + "Destination IP: <b>" + ip_to_str(ip.dst) + "</b><br>"
                desc = desc + "Destination Port: <b>" + str(tcp.dport) + "</b><br>"
                res = myevent.myevent(dateutil.parser.parse(date(ts)), "network" , "TCP Connection Syn", "Not Applicable", desc)
                result.append(res)
            elif syn_flag and ack_flag:
                desc = "Source IP: <b>" + ip_to_str(ip.src) + "</b><br>"
                desc = desc + "Source Port: <b>" + str(tcp.sport)  + "</b><br>"
                desc = desc + "Destination IP: <b>" + ip_to_str(ip.dst) + "</b><br>"
                desc = desc + "Destination Port: <b>" + str(tcp.dport) + "</b><br>"
                res = myevent.myevent(dateutil.parser.parse(date(ts)), "network" , "TCP Connection Syn-Ack", "Not Applicable", desc)
                result.append(res)
    
        # TODO Check if it is a FIN, if so end the connection
    
        # Try and parse what we have
        try:
            stream = conn[ tupl ]
            if stream[:4] == 'HTTP':
                http = dpkt.http.Response(stream)
                desc = "<b>" + ip_to_str(ip.src) + " --> " + ip_to_str(ip.dst) + "</b><br>"
                desc = desc + "<b> HTTP" + http.version + " " + http.status + " " + http.reason + "</b><br><br>"
                desc = desc + "Headers: <b>" + str(http.headers) + "</b><br><br>"
                if includecontent == "1":
                    desc = desc + "Content: <b>" + str(http.body) + "</b>"
                res = myevent.myevent(dateutil.parser.parse(date(ts)), "network", "HTTP Response", "Not Applicable", desc)
                result.append(res)
            else:
                http = dpkt.http.Request(stream)
                desc = "<b>" + ip_to_str(ip.src) + " --> " + ip_to_str(ip.dst) + "</b><br>"
                desc = desc + "<b>" + http.method + " " + http.uri + "</b><br><br>"
                desc = desc + "Headers: <b>" + str(http.headers) + "</b><br><br>"
                if includecontent == "1":
                    desc = desc + "Content: <b>" + str(http.body) + "</b>"
                res = myevent.myevent(dateutil.parser.parse(date(ts)), "network", "HTTP Request", "Not Applicable", desc)
                result.append(res)
    
            # If we reached this part an exception hasn't been thrown
            stream = stream[len(http):]
            if len(stream) == 0:
                del conn[ tupl ]
            else:
                conn[ tupl ] = stream
        except dpkt.UnpackError:
            pass

    f.close()
    
    return result

if __name__ == '__main__':
    import sys
    if len(sys.argv) <= 1:
        print "%s <pcap filename>" % sys.argv[0]
        sys.exit(2)

    parse_pcap_file(sys.argv[1])
