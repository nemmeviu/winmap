# winmap

Winmap is a module used in project hostfootprint-netbox.
Winmap module can search for windows hosts not parsed inside elasticsearch DB.
Map networks based on Netbox IPAM Project.


mapuser = os.getenv('MAPUSER')
es_server = os.getenv('ELASTICSEARCH')
country = os.getenv('COUNTRY')
DOMAIN = os.getenv('DOMAIN')


#### Variables for winmap

| ENV Vars     | value default   | description                           |
|--------------|:---------------:|:-------------------------------------:|
| DOMAIN       | blacktourmaline | windows/samba Domain Name             |
| MAPUSER      | _winmap         | User with permission on windows       |
| ES_SERVER    | 127.0.0.1	 | Elasticsearch Server IP/DNS name      |
| ES_INDEX     | nmap            | hostfootprint index name              |
| TENANT       | sistemas        | netbox tenant slug                    |

