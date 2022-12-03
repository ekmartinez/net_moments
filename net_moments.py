import psutil
import pandas as pd
from ipwhois import IPWhois

def lookup_who(ip):
    """Gets Whois information of external IPs"""
    lst = []
    
    #if IP is private it raises an error.
    try:
        obj = IPWhois(ip)
        who = obj.lookup_whois()['nets'][0]
        lst.append(who['description'])
        lst.append(who['state'])
        lst.append(who['country'])
        return lst
    except:
        return ['*', '*', '*']

#Data structure, container.
sight = {
        'LocalAddress':[],
        'LocalPort':[],
        'RemoteAddress':[],
        'RemotePort':[],
        'ProcessId':[],
        'Status':[],
        'Entity':[],
        'State':[],
        'Country':[]
        }

print('\nPlease wait, depending on the number of active connections,\n the whois service could be delayed.....\n')

#Populates data container.
for x in psutil.net_connections():
    if x.laddr:
        sight['LocalAddress'].append(x.laddr[0])
        sight['LocalPort'].append(x.laddr[1])
        if x.raddr:
            sight['RemoteAddress'].append(x.raddr[0])
            sight['RemotePort'].append(x.raddr[1])
            if x.status:
                sight['Status'].append(x.status)
                if x.pid == None:
                    sight['ProcessId'].append('N/A')
                else:
                    sight['ProcessId'].append(x.pid)

#Populates data container with whois info.
for addr in sight['RemoteAddress']:
    sight['Entity'].append(lookup_who(addr)[0])
    sight['State'].append(lookup_who(addr)[1])
    sight['Country'].append(lookup_who(addr)[2])

#converts to Pandas DataFrame for presentation.
pd.set_option('display.max_columns', None)
pd.set_option('display.width', 1000)
df = pd.DataFrame(sight)
print(f'{df}\n')


