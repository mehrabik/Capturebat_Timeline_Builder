# -*- coding: utf-8 -*-

import myevent
from dateutil import parser

def parseevent(strinput):
    parts = strinput.split(',')
    
    #parse time
    date = parser.parse(parts[0].replace("\"", ""))
    
    #parse type and sub type
    eventtype = parts[1].replace("\"", "")
    eventsubtype = parts[2].replace("\"", "")
    
    #parse owner
    owner = parts[3].replace("\"", "")
    
    #parse desc
    desc = parts[4].replace("\"", "").replace("\r","").replace("\n","")
    
    result = myevent.myevent(date, eventtype, eventsubtype, owner, desc)
    
    return result

