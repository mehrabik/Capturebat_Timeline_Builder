# -*- coding: utf-8 -*-
def createhtml(headername, logtype, name, events, outpath):
    
    header = open('html/header.html').read()
    footer = open('html/footer.html').read()
    fileopr = open('html/file.html').read()
    networkopr = open('html/network.html').read()
    processopr = open('html/process.html').read()
    registryopr = open('html/registry.html').read()
    
    #Open output file
    outfile = open(outpath + "/" + name + '.html', 'w')
    
    #Write header
    header = header.replace('%titletext%', headername + " " + logtype)
    header = header.replace('%name%', headername)
    header = header.replace('%logtype%', logtype)
    outfile.write(header)
    
    #Write events
    for event in events:
        outstr = ""
        
        if(event.eventtype == "file"):
            outstr = fileopr.replace('%date%', event.eventtime.strftime('%dth %B %y'))
            outstr = outstr.replace('%time%', event.eventtime.strftime('%H:%M:%S.%f')[:-3])
            outstr = outstr.replace('%subtype%', event.eventsubtype)
            outstr = outstr.replace('%desc%', 'Owner: <b>' + event.eventowner + "</b><br>" + "Argument: <b>" + event.eventdesc) + "</b>"
            
        elif (event.eventtype == "registry"):
            outstr = registryopr.replace('%date%', event.eventtime.strftime('%dth %B %y'))
            outstr = outstr.replace('%time%', event.eventtime.strftime('%H:%M:%S.%f')[:-3])
            outstr = outstr.replace('%subtype%', event.eventsubtype)
            outstr = outstr.replace('%desc%', 'Owner: <b>' + event.eventowner + "</b><br>" + "Argument: <b>" + event.eventdesc) + "</b>"
            
        elif (event.eventtype == "process"):
            outstr = processopr.replace('%date%', event.eventtime.strftime('%dth %B %y'))
            outstr = outstr.replace('%time%', event.eventtime.strftime('%H:%M:%S.%f')[:-3])
            outstr = outstr.replace('%subtype%', event.eventsubtype)
            outstr = outstr.replace('%desc%', 'Owner: <b>' + event.eventowner + "</b><br>" + "Argument: <b>" + event.eventdesc) + "</b>"
            
        elif (event.eventtype == "network"):
            outstr = networkopr.replace('%date%', event.eventtime.strftime('%dth %B %y'))
            outstr = outstr.replace('%time%', event.eventtime.strftime('%H:%M:%S.%f')[:-3])
            outstr = outstr.replace('%subtype%', event.eventsubtype)
            outstr = outstr.replace('%desc%', event.eventdesc)
            
        outfile.write(outstr)
        
        
    #Write footer
    outfile.write(footer)
    
    outfile.close()
            
    
    
    
        
    

