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

LISTMAPUSER = os.getenv('MAPUSER', 'localhost/_winmap,domain/Administrator').split(',')
LISTMAPPASS = os.getenv('MAPPASS', 'password1,password2').split(',')
if len(LISTMAPUSER) != len(LISTMAPPASS):
    print('MAPUSER and MAPPASS dont have some size of values')
    sys.exit(2)
COUNTRY = os.getenv('COUNTRY', '')
TENANT = os.getenv('TENANT', '')
DMZ = os.getenv('DMZ', '')

ES_SIZE_QUERY = int(os.getenv('ES_SIZE_QUERY', '10'))

ES_SERVER = os.getenv('ES_SERVER', '127.0.0.1')

index = os.getenv('ES_INDEX', 'nmap')
d = datetime.date.today()
ES_INDEX_SEARCH = index + '-*'
ES_INDEX_UPDATE = index + '-' + d.strftime('%m%Y')

ES_INDEX_TYPE = os.getenv('ES_INDEX_TYPE', 'nmap')
MAP_TYPE = 'windows'

TIMEOUT = int(os.getenv('TIMEOUT', '180'))

if (COUNTRY == '' and TENANT == ''):
    print('Please, create COUNTRY or TENANT env variable')
    sys.exit(2)

es = Elasticsearch( hosts=[ ES_SERVER ])

PROCS = int(os.getenv('PROCS', '10'))
try:
    WMICPROCS = int(os.getenv('WMICPROCS', '10'))
except:
    print('WMICPROCS is a number')
    sys.exit(2)

wmic_commands = {
    'Win32_OperatingSystem': '''SELECT Caption,FreePhysicalMemory from Win32_OperatingSystem''',
    'Win32_OperatingSystem_server': '''SELECT CSDVersion,CSName,ServicePackMajorVersion,LastBootUpTime from Win32_OperatingSystem''',
    'Win32_ComputerSystem': '''SELECT Model,Manufacturer,CurrentTimeZone,DaylightInEffect,EnableDaylightSavingsTime,NumberOfLogicalProcessors,NumberOfProcessors,Status,SystemType,ThermalState,TotalPhysicalMemory,UserName,Name from Win32_ComputerSystem''',
    'Win32_ComputerSystemProduct': '''SELECT IdentifyingNumber from Win32_ComputerSystemProduct''',
    'Win32_Processor': '''SELECT Name from Win32_Processor''',
    'Win32_Product': '''SELECT Name,Version from Win32_Product''',
    'Win32_QuickFixEngineering': '''SELECT HotfixID from win32_QuickFixEngineering''',
    'Win32_NetworkAdapterConfiguration': '''SELECT IPAddress,MACAddress,TcpNumConnections,DHCPServer,ServiceName from Win32_NetworkAdapterConfiguration'''
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
    'Product_Name',
    'Product_Version',
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
            pool.map(subproc_exec, hosts_args)
        time.sleep(1)

### END MP
def get_acess(host):
    '''
    check access in host.
    - if true, call subproc_exec
    - if false, save the fail status on elasticsearch
    '''

    result = {
        'parsed': 3,
        'err': 'not analyzed'
    }
    
    print(LISTMAPUSER)
    accessmode=False
    
    listpass = 0    
    for x in LISTMAPUSER:
        mapuser = x + '%' + LISTMAPPASS[listpass]
        wmictest = 'wmic -U "%s" //%s "%s"' % (
            mapuser,
            host['_source']['ip'],
            '''SELECT Caption from Win32_OperatingSystem'''            
        )
        
        subproc_CP = subprocess.run(
            wmictest,
            shell=True,
            timeout=TIMEOUT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if subproc_CP.returncode == 0:
            print('sucess access')
            accessmode=True
            break
        elif subproc_CP.returncode == 1:
            if subproc_CP.returncode == 1:

                DENIED=b'NTSTATUS: NT_STATUS_ACCESS_DENIED - Access denied\n'
                if subproc_CP.stderr == DENIED:
                    print('access denied!!!')

        listpass = listpass + 1
        
    if accessmode == True:
        subproc_exec(host, mapuser, result)
    else:
        result['parsed'] = 4
        result['err'] = "with out access"
            
    update_es(host['_id'], result)
        
def subproc_exec(host, mapuser, result):
    """
    in action
    """
    for k,v in wmic_commands.items():
        time.sleep(0.5)

        v = 'wmic -U "%s" //%s "%s"' % (mapuser, host['_source']['ip'], v)
        try:

            l_subproc = subprocess.check_output(v, shell=True, timeout=TIMEOUT)

            result['parsed'] = 0
            result['err'] = "analized"
        
            line = l_subproc.decode('utf-8', 'ignore').split('\n')
        
            # replace hostname
            if 'Win32_ComputerSystem' in line[0] and 'Win32_ComputerSystemProduct' not in line[0]:
                if '|Name' in line[1]:
                    line[1] = line[1].replace('|Name','|CSName')
            
            # Get all Products inside Windows 
            if 'Win32_Product' in line[0]:
                header = 'Product_Name'
                result[header] = []
                #line[1] = line[1].replace('Name','Product_Name')
                #line[1] = line[1].replace('Version','Product_Version')
                for product_new in line[2:-1]:
                    product_new = product_new.split('|')
                    product_final = (str(product_new[1])  + '=' + str(product_new[2]))
                    result[header].append(product_final)
                #print(result[header])
                #print(product_final)

                #build list Product_name in a Array_list
                #for product_member in line[2:-1]:
                # print(product_member)
                # product_member = product_member.replace('|','=')
                # result[header].append(product_member)


            # replace procinfo 
            if 'Win32_Processor' in line[0]:
                result['ProcName'] = []
                
                proc_name = line[2].split('|')
                result['ProcName'].append(proc_name[1])

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

    # fix ES error by boolean
    if 'DaylightInEffect' in result.keys():
        if result['DaylightInEffect'] == 'True':
            result['DaylightInEffect'] = True
        else:
            result['DaylightInEffect'] = False

    if 'EnableDaylightSavingsTime' in result.keys():            
        if result['EnableDaylightSavingsTime'] == 'True':
            result['EnableDaylightSavingsTime'] = True
        else:
            result['EnableDaylightSavingsTime'] = False            
    
    _id = _id
    # :-)
    body = {
        "doc": result
    }

    try:
        response = es.update(
            index=ES_INDEX_UPDATE,
            doc_type=ES_INDEX_TYPE,
            id=_id,
            body=body
        )
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
    if DMZ != '':
        LIST_TERMS.append(
            { "term": { "role": DMZ } }
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

    res = es.search(
        index=ES_INDEX_SEARCH,
        doc_type=ES_INDEX_TYPE,
        body=body,
        size=ES_SIZE_QUERY,
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
            pool.map(get_acess, nets)
            #pool.map(subproc_exec, nets)
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
