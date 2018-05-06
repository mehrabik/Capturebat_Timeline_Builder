# -*- coding: utf-8 -*-
#!/bin/env python2
import capturebateventparser
import createhtml
import getdns
import http
import sys
import os
import shutil
import pdfkit

def aggregate(events):
    finalevents = []
    idx = 0;
    added = 0;
    
    while idx < len(events):
        if(idx == 0):
            finalevents.append(events[idx])
            added = added + 1;
        elif(events[idx].compare(finalevents[added-1]) != 0):
            finalevents.append(events[idx])
            added = added + 1
        idx = idx + 1;
        
    return finalevents
    

def main(name, capture_path, pcap_path, outpath, includecontent):
    
    #Creating Output dir if not exists
    if not os.path.exists(outpath + "/" + name):
        os.makedirs(outpath + "/" + name)
    outpath = outpath + "/" + name + "/"
    
    #Copy assets to output
    shutil.copytree("./assets/", outpath + "/assets/")
    
    #Parse DNS Events and create html output
    print "Extracting DNS Queries..."
    dnsqueries = getdns.report(pcap_path)
    dnsqueries.sort(key=lambda x: x.eventtime, reverse=False)
    createhtml.createhtml(name, "DNS Queries Log", "dns", dnsqueries, outpath)
    
    #Parse TCP/Http Events and create html output
    print "Extracting TCP/HTTP Connections..."
    httpconns = http.parse_pcap_file(pcap_path, includecontent)
    httpconns.sort(key=lambda x: x.eventtime, reverse=False)
    createhtml.createhtml(name, "TCP/HTTP Connections Log", "tcp_http", httpconns, outpath)
    
    #Combine network events
    print "Creating Combined DNS TCP/HTTP Output..."
    networkevents = dnsqueries + httpconns
    networkevents.sort(key=lambda x: x.eventtime, reverse=False)
    createhtml.createhtml(name, "Network Operations Log", "network", networkevents, outpath)
    
    #Parse Capturebat events
    print "Parsing Capturebat Events..."
    fl = open(capture_path)
    lines = fl.readlines()
    capturebatevents = []
    for line in lines:
        a = capturebateventparser.parseevent(line)
        capturebatevents.append(a)
    capturebatevents.sort(key=lambda x: x.eventtime, reverse=False)
    
    #Split capture bat events and create output htmls
    print "Splitting Capturebat Events..."
    fileevents = []
    processevents = []
    registryevents = []
    for event in capturebatevents:
        if(event.eventtype == "file"):
            fileevents.append(event)
        elif (event.eventtype == "registry"):
            registryevents.append(event)
        elif (event.eventtype == "process"):
            processevents.append(event)
    
    #Creating File Events HTML Output
    print "Creating File Events Output..."
    fileevents.sort(key=lambda x: x.eventtime, reverse=False)
    fileevents = aggregate(fileevents)
    createhtml.createhtml(name, "File Operations Log", "file", fileevents, outpath)
    
    #Creating Registry Events HTML Output
    print "Creating Registry Events Output..."
    registryevents.sort(key=lambda x: x.eventtime, reverse=False)
    registryevents = aggregate(registryevents)
    createhtml.createhtml(name, "Registry Operations Log", "registry", registryevents, outpath)
    
    #Creating Process Events HTML Output
    print "Creating Process Events Output..."
    processevents.sort(key=lambda x: x.eventtime, reverse=False)
    processevents = aggregate(processevents)
    createhtml.createhtml(name, "Process Operations Log", "process", processevents, outpath)
    
    
    #Combine Events
    print "Combining All Events..."
    events = capturebatevents + dnsqueries + httpconns
    events.sort(key=lambda x: x.eventtime, reverse=False)
    
    #Aggregation
    print "Aggregating Events..."
    finalevents = aggregate(events)
        
    #Create HTML output
    print "Creating Combined HTML Output..."
    createhtml.createhtml(name, "Network/File/Registry/Process Operations Log", name, finalevents, outpath)
    
    #Create PDF Output
    print "Creating PDF Output..."
    pdfkit.from_file(outpath + "/" + name + ".html", outpath + "/" + name + ".pdf")


#Main Procedure    
if len(sys.argv) < 6:
    print "Usage: main.py <title> <path to capturebat output file> <path to pcap file> <path to a folder where the output will be written to> <put 1 if you want to include packet data in http log>"
    exit()
    
main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
