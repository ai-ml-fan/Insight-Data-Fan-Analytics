#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os.path
import re
import sys




#==== Tracks numer of requests by timestamp and top 10 active hours

from collections import deque,defaultdict,Counter
from datetime import timedelta,datetime

class MessagesPerTSTracker():
    '''#Class that tracks the maximum requests in any given hour'''
    '''#This class tracks the number of requests at any given timestamp'''
    '''It can also return the top 10 busiest hourly intervals'''
    '''The class uses a dictionary and a queue internally to track this'''
    '''The queue pops out the timestamp at the head only when the'''
    '''current timestamp exceeds the one hour window'''
    '''An improvement could be to only record the busiest 10 time intervals'''
    '''(or some pre-defined number)'''
    '''and discard the others.'''

    def __init__(self):
        #Initialize queue
        '''Create a deque object'''
        self.req_last_hr_q=deque()       
        #Initialize MaxRequestsLastHr to store 10 items
        self.max_requests_last_hr=[]
        #self.tscounter = defaultdict(Counter)
        self.tscounter = Counter()
        self.hour= timedelta(hours=1)
        self.fmt = "%d/%b/%Y:%H:%M:%S %z"
        
    def addtoTracker(self, ts, isLast=False):
        adj = 0
        timestamp = None
        if not isLast:
            timestamp = datetime.strptime(ts, self.fmt)
            self.req_last_hr_q.append(timestamp)
            adj = 1
            
        if len(self.req_last_hr_q) == 0: return

        while (timestamp and timestamp - self.req_last_hr_q[0] >= self.hour) or isLast:
            ts = self.req_last_hr_q.popleft()
            key = ts.strftime(self.fmt)
            
            if not self.tscounter[key]:
                self.tscounter[key] = len(self.req_last_hr_q) + 1 - adj
                
            if len(self.req_last_hr_q) == 0:
                break
            
    '''Define a function that computes the top number (default=10) of requests'''
    '''in the last hour '''
    
    def max_active(self,topcount=10):
        self.addtoTracker(ts='',isLast=True)
        '''Returns a tuple of timestamp and number of messages in the last hr'''
        max_requests_last_hr = self.tscounter.most_common(topcount)
        return max_requests_last_hr
        
#==== Reads website log file and summarizes key metrics such as most-often accessed resources,hosts,busiest period etc 

import csv

class WebLogReader():
    '''Read the log.txt file'''
    '''Split into hostname, dates, url,code, size'''
    '''For each line, create a map of hostname and increase value for each access'''
    '''Read arg to check directory'''

    ''' This class analyses failed attempts to detect potential threats'''
    def __init__(self,filepath):
        self.trkr = MessagesPerTSTracker()
        self.counters = defaultdict(Counter)
        self.failed = dict()
        self.blocked =dict()
        self.linecount = 0
        self.fmt = "%d/%b/%Y:%H:%M:%S %z"
        self.timeout = timedelta(seconds=20)
        self.blockedtimeout = timedelta(minutes=5)
        self.__writeblockedto(filepath)
        self.curr_line = None

    '''TODO: Define datetime overloading'''
    def __sub__(self, dt1,dt2):
        #print("2. sub:~",dt1,"~",dt2)
        ts1 = datetime.strptime(dt1, self.fmt)
        ts2 = datetime.strptime(dt2, self.fmt)
        return ts1 - ts2
    
    def __writeblockedto(self,blocked="./blocked.txt"):
        self.blkfilepath = blocked
        self.blockedfilewriter= open(blocked,"w+")
        
    def _update(self,**kwargs):
        
        self.linecount += 1
        sz = kwargs['sz']
        res = kwargs['resource']
        retcode=kwargs['retcode']
        host = kwargs['host']
        ts = kwargs['timestamp']                   

        #print(sz)
        for key, value in kwargs.items():
            if key in ('host','timestamp','retcode'):
                self.counters[key][value] += 1
        if res:
            self.counters['resource'][res] += sz
        self.trkr.addtoTracker(ts)       
        #print(kwargs['host'],kwargs['resource'],sz,res,kwargs['retcode'])


    def _logasblocked(self,host,ts):
        self.blockedfilewriter.write(self.curr_line+'\n')
        #print("LOGGING:",self.curr_line)
        if not host in self.blocked or self.blocked[host] == False:
            self.blocked[host] = True
            self.failed[host] = ts
        self.blockedfilewriter.flush()
        #print("2.LOGGING:",self.curr_line)
        return 3
        #os.fsync(f.fileno())


    def complete(self):
        self.blockedfilewriter.close()
        
       
    @staticmethod
    def _parse(line):
        #first sep
        firstsep =' - - ['
        host,tokens = line.split(firstsep,1)
        secondsep = '] '
        #Timestamp in tokens[1]
        ts,tokens = tokens.split(secondsep,1)
        retcode,sz = line.split()[-2:]

        #If retcode shows invalid request, return
        if '400' in retcode:
            return {'host':host, 'timestamp':ts,'resource':None, 'retcode':retcode, 'sz':0 }
                   
        if '-' in sz:
            sz = 0
        sz=int(sz)
        
        tok = re.match(r'(["“])(.+)(["”])',tokens)
        #Now process resource *only* if status code != 400
        resource=''
        if tok:
            resource= tokens[tok.start()+1:tok.end()-1].split()
            if len(resource) < 2:
                print("Resource < 2",resource)
                print(retcode,sz)
            else:
                resource =resource[1]       
        return {'host':host, 'timestamp':ts,'resource':resource, 'retcode':retcode, 'sz':sz }

    def most_accesses_by(self,count=10):
        return  self.counters['host'].most_common(count)
        
    def most_accessedlarge_resources(self,count=10):
        #print(self.counters['resource'].most_common(count))
        return  self.counters['resource'].most_common(count)
    
    def most_active_1hrperiods(self,count=10):
        return self.trkr.max_active(count)
    
    def analyse(self,infile):
        '''Clear Blocked'''
        def _clearblock(self):
            self.blocked[host] = False
            self.blocked.pop(host)
            self.failed[host] = None
            self.failed.pop(host)

        '''Clear Failed'''
        def _clearfailed(self):
            self.counters['failed'][host] = 0
            self.counters['failed'].pop(host)
            self.failed[host] = None
            self.failed.pop(host)
                            

        with open(infile, 'r',errors="replace") as f:
            for line in f:
                setfailed = False
                blocked = False
                
                line=line.strip()
                self.curr_line = line
                
                rest,retcode,sz= line.rsplit(None,2)

                '''Set failedrequest based on HTTP reply code. '''
                '''All HTTP reply codes 4xx indicate user denied codes. '''
                failedrequest = True if len(retcode) == 3 and retcode.startswith('4') else False

                firstsep =' - - ['
                host,j,rest = rest.partition(firstsep)
                secondsep = '] '
                
                #Timestamp in tokens[1]
                ts = rest.split(secondsep,1)[0]

                ''' Check if this host is blocked'''
                blocked = True if host in self.blocked and self.blocked[host] else False                 
                ''' *Condition* If this host is in the 5 minute blocked period '''
                ''' *then*      Log this request in the blocked.txt file '''
                ''' *Else*      Clear the blocked flag as this request is beyond the blocked period'''
                if blocked:
                    self._logasblocked(host,ts) if self.__sub__(ts,self.failed[host])  < self.blockedtimeout else _clearblock(self)
                elif failedrequest:
                    '''If this status has failed with a 4xx http code(this is the code for user denied):'''
                    '''If first fail, Set failed time and start counter. Next fail, check if this happened within timeout 20sec.'''
                    '''If failed within the window, < 20, increment counter. till 3.'''
                    '''          If failed 3 times, "block" host and write to file'''
                    ''' Otherwise,if window > 20 reset counter to 0.'''
                    ''' the next block will take care to reset failed state and counter if a valid request is made'''
                    '''Note that we only check the return code for non-blocked hosts'''
                                       
                                
                    # Set failed to True only under the following conditions'''
                    # *Condition 1* : if this is the First failed request ever or first failure in the last 20 seconds'''
                    # *Condition 2* : Exceeds 20 second window. This is the same case as if the host failed for the first time.'''
                    setfailed = True if not host in self.failed or not self.__sub__(ts,self.failed[host]) < self.timeout else False
                    
                    '''Check if the host has made past invalid requests and is not currently "blocked"'''                   
                    if host in self.failed:
                        #print("Failed request: ",retcode,"~",host,"~",ts,"~",self.failed[host])
                        '''Check if this invalid request is within 20 seconds of the last failed request'''
                        if self.__sub__(ts,self.failed[host])  < self.timeout:
                            '''Increment counter  upto 3. If already 3, "block" this host'''
                            self.counters['failed'][host] += 1 if self.counters['failed'][host] < 3 else self._logasblocked(host,ts)                       
                else:
                    '''If this is a valid request, reset failed state and counter if last request had failed for some reason'''
                    '''Note that we only check the return code for non-blocked hosts'''            

                    if host in self.failed:
                        _clearfailed(self)
                        #print("Reset failedstate for host :",host,retcode,ts)

                '''Record the failure'''                                                    
                if setfailed:
                    '''Record this request was invalid. Increment the failed counter and record the timestamp for this host'''
                    #print("set failed:",retcode,host,ts)
                    self.counters['failed'][host] = 1
                    self.failed[host] = ts 
                    #print("FAILED[host]:",self.failed[host])
                     
                if '-' in sz:
                    sz = '0'

                sz=int(sz)
                #print("CHECK RETCODE:",retcode,host,ts)
                self._update(**self._parse(line))                
            
try :
    '''Simple method to retrieve all arguments'''
    id=0
    for arg in sys.argv:
        print("Arg ",id,arg)
        id += 1
    args = len(sys.argv)

    
    
    '''This is the main start of the program'''
    '''Read the file and create host and resource dictionaries'''
    path = '../log_input/'   
    #path = './log_input/'   
    infile= path+"log.txt" if args < 2 else sys.argv[1]
    
    outpath = '../log_output/'
    #outpath = './log_output/'
    writeblockedtofile = outpath + "blocked.txt" if args < 6 else sys.argv[5] 
       
    hostpath=outpath+"hosts.txt" if args < 3 else sys.argv[2]
    hrspath=outpath+"hours.txt" if args < 4 else sys.argv[3]
    respath=outpath+"resources.txt" if args < 5 else sys.argv[4]

    print("(Input Log File to be read:",infile, ")")
    print("(O/P Hosts file :",hostpath,")")
    print("(O/P Hours file:",hrspath,")")
    print("(O/P Resources file:",respath,")")
    print("(Output Blocked file:",writeblockedtofile,")")

    ''' Start of main'''
    '''Create a WebLogReader'''
    '''Analyse the input file'''
    
    reader = WebLogReader(writeblockedtofile)
    reader.analyse(infile)
    reader.complete()

    '''Now List the top 10 most active host/IP addresses that have'''
    '''accessed the site.'''   
    with open(hostpath, 'w') as out:
        for key,val in reader.most_accesses_by(10):
            out.write(key+','+str(val)+'\n')
        
    '''Identify the top 10 resources on the site that consume the most bandwidth.'''
    with open(respath, 'w') as res:
        for key,val in reader.most_accessedlarge_resources(10):
            res.write(key+'\n')
       
    with open(hrspath, 'w') as hrs:
        for key,val in reader.most_active_1hrperiods(10):
            hrs.write(key+','+str(val)+'\n')
            
#TODO: ENHANCE LOGGING TO TRACK THE OFFENDING LINE AND POSSIBLE STACKTRACE          
except(ValueError, TypeError, NameError) as err:    
    print("In exception: ", err.args)
    print(err)

    

