# -*- coding: utf-8 -*-
class myevent:
    
    def __init__(self, eventtime, eventtype, eventsubtype, eventowner, eventdesc):
        self.eventtime = eventtime
        self.eventtype = eventtype
        self.eventsubtype = eventsubtype
        self.eventdesc = eventdesc
        self.eventowner = eventowner
        
    def compare(self, obj):
        if(self.eventtype == obj.eventtype):
            if(self.eventsubtype == obj.eventsubtype):
                if(self.eventowner == obj.eventowner):
                    if(self.eventdesc == obj.eventdesc):
                        return 0;
        return 1;
                        
                            
            

