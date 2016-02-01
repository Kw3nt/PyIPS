#!/bin/python
#-*- coding:utf-8 -*-


from netfilterqueue import NetfilterQueue
from dpkt.ip import IP
from dpkt.tcp import TH_ACK, TH_FIN, TH_SYN, TH_RST, TH_PUSH, TH_URG, TH_ECE, TH_CWR
from socket import inet_ntoa, getfqdn
from requests import get
from threading import Thread
from time import sleep
from hashlib import md5
from virus_total_apis import PublicApi

class Singleton(type):
    ''' METACLASS USED FOR TCP_SESSION_TABLE '''
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

class tcp_session_list(list):
    ''' CLASS USED FOR TCP_SESSION_TABLE'''
    __metaclass__ = Singleton
    pass

class lock(list):
    ''' CLASS USED FOR LOCK '''
    __metaclass__ = Singleton
    pass


def search_session_in_table(session, table):
    # session:[src, sport, dst, dport]
    # table: [[[src, sport, dst, dport], type, fasrc, fadst, fa1st], ...]
    # table[index]: [[src, sport, dst, dport], type, fasrc, fadst, fa1st]
    # table[index][0]: [src, sport, dst, dport]
    try:
        for index in xrange(len(table)):
            if table[index][0] == session:
                return False, index
            if table[index][0][:2] == session[2:] and table[index][0][2:] == session[:2]:
                return True, index
    except IndexError:
        return False, False
    return False, False

def dissect_flag(flag):
    dissected = {}    
    for item in [TH_FIN, TH_ACK, TH_SYN, TH_RST, TH_PUSH, TH_URG, TH_ECE, TH_CWR]:
        dissected[item]=(flag & item) != 0
    return dissected



def link_to_virustotal(link, pkt):
    ''' IN CASE WE FOUND GET link, WE SCAN IT '''
    print 'SCANNING %s'%link
    virus_total_instance = PublicApi('2e1d7b6e998ed0a9830269571ecffa110e41dd8bf34b88ad41e40b4351165d18')
    REQ = virus_total_instance.scan_url(link)
    print 'Waiting for virustotal'
    while True:
        if 'Scan finished' in str(virus_total_instance.get_url_report(link)):
            print 'Scan finished!'
            REP = virus_total_instance.get_url_report(link)['results']['positives']
            break
        else:
            print 'Naaa not yet'
    if REP == '0' or REP == 0:
        print 'SCANNED %s - VERDICT OK [REP=%s]'%(link,REP)
        pkt.accept()
    else:
        print 'SCANNED %s - VERDICT KO [REP=%s]'%(link,REP)
        pkt.drop()
    '''
    try:
        return REQ['results']['positives']
    except KeyError:
        print REQ
    '''

# [[[source, sport, dest, dport], type, FASRC, FADST, FA1ST, ...],]
def update_table(table, packet, index, reverse):
    # Maybe faire les check sur les flags avec le binaire ?
    # if packet.tcp.flags == 16:
    #     print 'FLAG: A'
    #     action = 0
    # elif packet.tcp.flags == 17 or packet.tcp.flags == 25:
    #     print 'FLAG: FA'
    #     action = 1
    # else:
    #     print 'FLAG: %s'%packet.tcp.flags
    #     action = False
    dissected = dissect_flag(packet.tcp.flags)
    if (dissected[TH_FIN] is True and dissected[TH_ACK] is True):
        print 'FLAG: FA'
        action = 1
    elif dissected[TH_ACK] is True:
        print 'FLAG: A'
        action = 0
    elif dissected[TH_RST] is True:
        print 'FLAG: RST'
        table.pop(index)
        return table
    else:
        #print 'FLAGS: %s'%repr(dissected)
        action = False
    if reverse:
        # SRC = DST in TABLE
        if table[index][3] is False and action == 1:
            # Si FASRC = False et FLAG PACKET = FA
            table[index][3] = True # On change la valeur dans la table
            table[index][4] = False # FA1ST is DST
        elif table[index][3] is True and table[index][2] is True and table[index][4] is False and action == 0 :
            # Si FASRC = True et FADST = True et FA1ST = True (= src) et FLAG PACKET = A
            table.pop(index) # alors on peut supprimer la session de la table
    else:
        # SESSION IS AS IN TABLE
        ################ DANS LE CADRE D'UNE FERMETURE DE SESSION FA -> FA -> A
        if table[index][2] is False and action == 1:
            # Si FASRC = False et FLAG PACKET = FA
            table[index][2] = True # On change la valeur dans la table
            table[index][4] = False # FA1ST is SRC
        elif table[index][2] is True and table[index][3] is True and table[index][4] is True and action == 0:
            # Si FASRC = True et FADST = True et FA1ST = True (= src) et FLAG PACKET = A
            table.pop(index) # alors on peut supprimer la session de la table
        ################ DANS LE CADRE D'UNE FERMETURE DE SESSION FA -> FA -> A
    return table




def callback(pkt):
    ''' CALLBACK FUNCTION WITH PACKET FROM NFQUEUE '''
    tcp_session_table = tcp_session_list([])
    packet = IP(pkt.get_payload()) 
    HTTP = [80, 8080]
    HTTPS = [443, 8443]
    EXTENSIONS = ['.pdf', '.exe', '.docx', '.doc', '.php', '.apk', '.ini']
    if 'tcp' in dir(packet):
        print '-'*30 + '> NEW TCP PACKET <' + '-'*30
        print 'SRC: %s'%inet_ntoa(packet.src)
        print 'DST: %s'%inet_ntoa(packet.dst)
        print 'SPORT: %s'%packet.tcp.sport
        print 'DPORT: %s'%packet.tcp.dport
        session = [inet_ntoa(packet.src), packet.tcp.sport, inet_ntoa(packet.dst), packet.tcp.dport]
        reverse, index = search_session_in_table(session, tcp_session_table)
        #print 'REVERSE: %s'%reverse
        #print 'INDEX: %s'%index
        if index is False:
            tcp_session_table.append([session, None, False, False, None])
        else:
            tcp_session_table = update_table(tcp_session_table, packet, index, reverse)
        #print 'TCP_TABLE [LEN %s] :\n%s'%(len(tcp_session_table),tcp_session_table)
        if packet.tcp.sport in HTTPS or packet.tcp.dport in HTTPS:
            print 'Yayyyy we found Some HTTPS DATA'
            pkt.accept()
            #print 'DATA: [ENCRYPTED HTTPS DATA]'
        elif packet.tcp.sport in HTTP or packet.tcp.dport in HTTP:
            print 'This is HTTP, WE MIGHT DO SOME STUFF <3'
            if 'GET' in packet.tcp.data:
                print 'User requests a payoad !'
                act = packet.tcp.data.split('GET')[1].split('HTTP')[0]
                print 'he wants %s'%act
                if len(act) > 1:
                    link = 'http://%s%s'%(inet_ntoa(packet.dst),act.replace(' ',''))
                    head_req = get(link)
                    if not 'html' in head_req.text[:5] and head_req.status_code != 404:
                        for extension in EXTENSIONS:
                            if extension in act or extension in head_req.text[:5]:
                                #WE NEED TO VIRUSTOTAL IT
                                #print 'WHAT ABOUT VIRUSTOTAL IT?'
                                #link_to_virustotal(link,pkt)
                                pkt.accept()
                                break
                    else:
                        print 'We receive HTML code OR 404 when following the link. Its a webpage OR the link is available only once, OR the site is not accessible by its ip and DNS isn\'t totally setup'
                        pkt.accept()
                else:
                    pkt.accept()
            else:
                pkt.accept()



    elif 'udp' in dir(packet):
        pkt.accept()
        print '-'*30 + '> NEW UDP PACKET <' + '-'*30
        print 'SRC: %s'%inet_ntoa(packet.src)
        print 'DST: %s'%inet_ntoa(packet.dst)
        print 'SPORT: %s'%packet.udp.sport
        print 'DPORT: %s'%packet.udp.dport
        if len(packet.udp.data) > 0:
            print 'DATA: %s'%repr(packet.udp.data)
            pass
    #print '-'*30 + '> PACKET  OK <' + '-'*30


def launch_nfqueue(num):
    nfqueue = NetfilterQueue()
    nfqueue.bind(num, callback)
    sleep(1)
    while lock([])[0] is False:
        print '#'*10 + '-'*10 + '> Bound to queue %s <'%num + '-'*10 +'#'*10
        nfqueue.run()
        print '#'*10 + '-'*10 + '> Queue %s had to restart <'%num + '-'*10 + '#'*10
    print '#'*10 + '-'*10 + '> Queue %s got SIGSTOP <'%num + '-'*10 + '#'*10
    nfqueue.unbind()



def main():
    ''' INIT '''
    stoplock = lock([])
    stoplock.append(False)
    for num in [10,11]:
        thread =  Thread(group=None, target=launch_nfqueue, args=(num, ))
        thread.setDaemon(True)
        thread.start()
    print 'IDS Started. Press ^C to stop'
    while True:
        try:
            sleep(0.1)
        except KeyboardInterrupt:
            print '\rExiting'
            stoplock[0] = True
            exit(0) 

if __name__ == '__main__':
    main()
