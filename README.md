# winmap

Winmap is a module used in project [hostfootprint-netbox](https://github.com/nemmeviu/hostfootprint-netbox/).
Winmap search for windows hosts inside elasticsearch DB and
execute a serie of calls to extract informations.

#### Variables for winmap

| env vars      | default value                            | description                            |
|--------------:|:----------------------------------------:|:--------------------------------------:|
| MAPUSER       | localhost\_winmap,domain\Administrator   | domain\user separated by "," if many   |
| MAPPASS       | password1,password2                      | Password of users in order. sep by "," |
| ES_SERVER     | 127.0.0.1                                | Elasticsearch Server IP/DNS name       |
| ES_INDEX      | nmap	                                   | Indice elasticsearch                   |
| ES_INDEX_TYPE | nmap	                                   | Type object inside index elasticsearch |
| TENANT        | False                                    | Netbox Tenant slug                     |
| COUNTRY       | False                                    | Netbox Country Name (Region Father)    |
| WMICPROCS     | 10                                       | Number of threads wmic in some time    |
| PROCS         | 10                                       | Number of hosts mappeds in some time   |
| TIMEOUT       | 180					   | Whait Timeout in seconds	     	    |


Here one mapping of the final object:
```
mapping = {
    "mappings": {
        index_type:{
            "properties": {
                "g_last_mod_date": {
	            "type": "date",
	            "format": "epoch_millis"
                },
                "g_country": {
                    "index": "true", 
                    "type": "keyword"
                },
                "g_flag": {
                    "index": "true", 
                    "type": "keyword"
                },
                "g_businessunit": {
                    "index": "true", 
                    "type": "keyword"
                },
                "g_application": {
                    "index": "true", 
                    "type": "keyword"
                },
                "g_kpi": {
	            "type": "boolean"
                },
                "g_critical": {
	            "type": "boolean"	    
                },
                "situation": {
                    "index": "true", 
                    "type": "keyword"
                },
                "physical_address": {
                    "index": "true", 
                    "type": "keyword"
                },
                "city": {
                    "index": "true", 
                    "type": "keyword"
                },
                "geo_location": {
	            "type": "geo_point"
                },
	        "local_desc": {
	            "index": "true", 
                    "type": "keyword"
                },
                "map_type": {
                    "index": "true", 
                    "type": "keyword"
                },
                "local_id": {
                    "index": "true", 
                    "type": "keyword"
                },
	        "local_address": {
	            "index": "true", 
                    "type": "keyword"
                },
                "sites": {
	            "type": "integer"
                },
                "network": {
                    "index": "true", 
                    "type": "keyword"
                },
                "ip": {
                    "type": "ip"
                },
	        "hostname": {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "parsed": {
                    "type": "short"
	        },
	        "exit_code": {
                    "type": "short"
	        },
	        "Caption": {
	            "index": "true", 
                    "type": "keyword"
	        },	    
	        "FreePhysicalMemory": {
	            "type": "long"
	        },
	        "TotalPhysicalMemory": {
	            "type": "long"
	        },
	        "Model": {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "CurrentTimeZone": {
	            "type": "short"
	        },
	        "DaylightInEffect": {
	            "type": "boolean"
	        },
	        "EnableDaylightSavingsTime": {
	            "type": "boolean"
	        },
	        "NumberOfLogicalProcessors": {
	            "type": "short"
	        },
	        "NumberOfProcessors": {
	            "type": "short"
	        },
	        "ProcFamily": {
	            "type": "short"
	        },
	        "ProcLoadPercentage": {
	            "type": "short"
	        },
	        "ThermalState": {
	            "type": "short"
	        },
	        "Vendor": {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "err": {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "ProcManufacturer": {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "ProcName": {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "Status": {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "SystemType": {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "IdentifyingNumber": {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "LoadPercentage": {
	            "type": "short"
	        },
	        "Manufacturer": {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "Name": {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "CSName": {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "LastBootUpTime": {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "ServicePackMajorVersion": {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "HotFixID": {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "OSArchitecture": {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "Product": {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "SerialNumber": {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "UUID": {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "UserName": {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "Version" : {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "Name_AV" : {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "Version_AV" : {
	            "index": "true", 
                    "type": "keyword"
	        },
	        "HotFixID" : {
	            "index": "true", 
                    "type": "keyword"
	        }
            }
        }
    }
}

```
