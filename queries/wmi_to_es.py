#!/usr/bin/env python3

import sys, time, os, subprocess, sys, json, re, datetime
from multiprocessing import Manager
#from multiprocessing import Pool
from multiprocessing.pool import ThreadPool
from threading import Thread, Lock

from elasticsearch import Elasticsearch

from subprocess import STDOUT, CalledProcessError, check_output as qx

class EstadoNaoDeterminado(Exception):
    pass

LISTMAPUSER = os.getenv('MAPUSER', 'localhost\_winmap,domain\Administrator').split(',')
LISTMAPPASS = os.getenv('MAPPASS', 'password1,password2').split(',')
if len(LISTMAPUSER) != len(LISTMAPPASS):
    print('MAPUSER and MAPPASS dont have some size of values')
    sys.exit(2)
COUNTRY = os.getenv('COUNTRY', '')
TENANT = os.getenv('TENANT', '')  
ES_SERVER = os.getenv('ES_SERVER', '127.0.0.1')

ES_INDEX = os.getenv('ES_INDEX', 'nmap')
d = datetime.date.today()
ES_INDEX = ES_INDEX + '-' + d.strftime('%m%Y')

ES_INDEX_TYPE = os.getenv('ES_INDEX_TYPE', 'nmap')
MAP_TYPE = 'windows'

if (COUNTRY == '' and TENANT == ''):
    print('Please, create COUNTRY or TENANT env variable')
    sys.exit(2)

es = Elasticsearch( hosts=[ ES_SERVER ])

PROCS=1
try:
    WMICPROCS = int(os.getenv('WMICPROCS', '8'))
except:
    print('WMICPROCS is a number')
    sys.exit(2)

wmic_commands = {
    'Win32_OperatingSystem': 'SELECT Caption,FreePhysicalMemory from Win32_OperatingSystem',
    'Win32_OperatingSystem_server': 'SELECT CSDVersion,CSName,ServicePackMajorVersion,LastBootUpTime from Win32_OperatingSystem',
    'Win32_ComputerSystem': 'SELECT Model,Manufacturer,CurrentTimeZone,DaylightInEffect,EnableDaylightSavingsTime,NumberOfLogicalProcessors,NumberOfProcessors,Status,SystemType,ThermalState,TotalPhysicalMemory,UserName,Name from Win32_ComputerSystem',
    'Win32_ComputerSystemProduct': 'SELECT IdentifyingNumber from Win32_ComputerSystemProduct',
    'Win32_Processor': 'SELECT Family,LoadPercentage,Manufacturer,Name from Win32_Processor',
    'Win32_Product': '''SELECT Name,Version from Win32_Product where Name='Symantec Endpoint Protection' ''',
    'Win32_QuickFixEngineering': 'SELECT HotfixID from win32_QuickFixEngineering',
    'Win32_NetworkAdapterConfiguration': 'SELECT IPAddress,MACAddress,TcpNumConnections,DHCPServer,ServiceName from Win32_NetworkAdapterConfiguration'
}

wmic_rows = [
    'Caption',
    'Model',
    'Manufacturer',
    'CurrentTimeZone',
    'DaylightInEffect',
    'EnableDaylightSavingsTime',
    'NumberOfLogicalProcessors',
    'NumberOfProcessors',
    'Status',
    'SystemType',
    'ThermalState',
    'TotalPhysicalMemory',
    'FreePhysicalMemory',
    'UserName',
    'hostname',
    'Name',
    'IdentifyingNumber',
    'ProcFamily',
    'ProcLoadPercentage',
    'ProcManufacturer',
    'ProcName'
    'CSDVersion',
    'CSName',
    'ServicePackMajorVersion',
    'LastBootUpTime',
    'Name_AV',
    'Version_AV',
    'HotFixID',
    'IPAddress',
    'MACAddress',
    'DHCPServer',
    'ServiceName'
]

###### MP
def get_hosts_and_clear():
    result = []
    while len(hosts_shared_lists) > 0:
        result.append(hosts_shared_lists.pop())
    return(result)

def get_nets_and_clear():
    result = []
    while len(nets_shared_lists) > 0:
        result.append(nets_shared_lists.pop())
    return(result)

def do_wmic():
    pool = ThreadPool(processes=WMICPROCS)
    while not shared_info['finalizar'] or len(hosts_shared_lists) > 0:
        hosts_args = get_hosts_and_clear()
        if len(hosts_args) > 0:
            pool.map(subproc_exec, hosts_args )
        time.sleep(1)

### END MP
def subproc_exec(host):
    """
    in action
    """
    result = {
        'parsed': 3,
        'err': 'not analyzed'
    }
    
    for k,v in wmic_commands.items():
        time.sleep(0.5)

        #
        print(LISTMAPUSER)
        for x in LISTMAPUSER:
            listpass = 0
            print(x)

            mapuser = x + '%' + LISTMAPPASS[listpass]
            v = 'wmic -U "%s" //%s "%s"' % (mapuser, host['_source']['ip'], v)

            listpass = listpass + 1

        try:

            l_subproc = subprocess.check_output(v, shell=True, timeout=100)

            result['parsed'] = 0
            result['err'] = "analized"

            line = l_subproc.decode().split('\n')

            # replace hostname
            if 'Win32_ComputerSystem' in line[0] and 'Win32_ComputerSystemProduct' not in line[0]:
                if '|Name' in line[1]:
                    line[1] = line[1].replace('|Name','|CSName')
            
            # replace AV Information
            if 'Win32_Product' in line[0]:
                line[1] = line[1].replace('Name','Name_AV')
                line[1] = line[1].replace('Version','Version_AV')

            # replace procinfo 
            if 'Win32_Processor' in line[0]:
                line[1] = line[1].replace('Family','ProcFamily')
                line[1] = line[1].replace('LoadPercentage','ProcLoadPercentage')
                line[1] = line[1].replace('Manufacturer','ProcManufacturer')
                line[1] = line[1].replace('Name','ProcName')

            if k == 'Win32_QuickFixEngineering':
                header = 'HotFixID'
                result[header] = []

                for fix in line[2:-1]:
                    fix = fix.replace('|', '')
                    result[header].append(fix)
            else:
                # default output
                header = line[1].split('|')
                info = line[2].split('|')

                pointer = 0
                while pointer < len(header):
                    if header[pointer] in wmic_rows:
                        result[header[pointer]] = info[pointer]
                    pointer = pointer + 1

        except subprocess.CalledProcessError as time_err:
            result['parsed'] = time_err.returncode
            result['err'] = "%s - %s" % (str(time_err.output), str(time_err.stderr) )


        except subprocess.TimeoutExpired as timeout:
            result['parsed'] = 1
            result['err'] = "%s - %s" % (str(timeout.output), str(timeout.stderr) )

        except:
            result['parsed'] = 3
            result['err'] = "not analyzed"
            
    update_es(host['_id'], result)

###############
def update_es(_id, result):
    
    _id = _id
    # :-)
    body = {
        "doc": result
    }

    try:
        response = es.update(
            index=ES_INDEX,
            doc_type=ES_INDEX_TYPE,
            id=_id,
            body=body
        )
        print(response)
    except:
        print("fail: %s" % _id)

def get_ip():

    LIST_TERMS = [
        { "exists": { "field": "ip" } },
        { "term": { "map_type": MAP_TYPE } }        
    ]
    
    if COUNTRY != '':
        LIST_TERMS.append(
            { "term": { "g_country": COUNTRY } }
        )
    if TENANT != '':
        LIST_TERMS.append(
            { "term": { "g_flag": TENANT } }
        )

    body = {
        "sort" : [
            { "g_last_mod_date" : {"order" : "desc"}},
        ],
        "query": {
            "bool": {
                "must_not": {
                    "exists": { "field": "parsed" }
                },
                "must": LIST_TERMS
            }
        }
    }

    print(body)

    res = es.search(
        index=ES_INDEX,
        doc_type=ES_INDEX_TYPE,
        body=body,
        size=200,
    )

    ips = []
    for doc in res['hits']['hits']:
        ips.append(doc)
    return(ips)

def main():
    
    shared_info['finalizar'] = False

    # query elasticsearch
    ips = get_ip()
    print(len(ips))

    for host in ips:
        nets_shared_lists.append(host)

    t = Thread(target=do_wmic)
    t.start()

    pool = ThreadPool(processes=PROCS)
    while len(nets_shared_lists) > 0:
        nets = get_nets_and_clear()
        if len(nets) > 0:
            pool.map(subproc_exec, nets)
        time.sleep(1)
            
    shared_info['finalizar'] = True
    t.join()


manager = Manager()
hosts_shared_lists = manager.list([])
hosts_error_list = manager.list([])
nets_shared_lists = manager.list([])
shared_info = manager.dict()
        
if __name__ == "__main__":
    main()
