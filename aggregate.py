from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q
import sys
from pprint import pprint
import datetime
import ipaddress

from userlog import UserLog

def all_aggregation(mask=24):
    """ 
    Finds the list of all districts.
    
    Computes the average reputation for each peer.
    
    Grabs the latest attacker-based aggregation with cidrs enabled
    and then aggregates all attackers and their
    corresponding cidrs into a single document.
    """
    userlog = UserLog()

    es_client= Elasticsearch()

    rep_index= 'reputations'
    if not es_client.indices.exists(index=rep_index):
        userlog.error('No collaborators are involved')
        sys.exit()

    find_district_list = Search(using=es_client, index=rep_index) \
                        .query(~Q('match', _type='average_rep')) \
                        .query('match', _id=1)
    response = find_district_list.execute()

    userlog.info('Calculating the average reputations of every district...')
    avg_reps = calculate_avg_reps(es_client, rep_index, response)
    
    results={}
    for hit in response:  # Each hit represents a different collaborator
        collaborator = hit.meta.doc_type
        district_index = collaborator + '-aggrevents-*'
        find_latest_doc = Search(using=es_client, index=district_index, doc_type='auth') \
                        .query('match', aggregation_type='attacker') \
                        .sort('-@timestamp') \
                        .extra(size=1)
        resp = find_latest_doc.execute()
        
        # If there is no aggregation pushed from a district, skip it
        if not resp:
            continue
        district_aggr = resp[0]

        for attacker in district_aggr['attackers']:
            if attacker['attacker_ip'] in results:
                results[attacker['attacker_ip']]['attempts'] += attacker['attempts']
                results[attacker['attacker_ip']]['reporters'].append(collaborator)
            else:
                results[attacker['attacker_ip']] ={
                    'attempts': attacker['attempts'],     
                    'reporters': [collaborator]
                }
    global_attackers = ddict_to_ldict(results)
    cidrs = ips_to_cidrs(global_attackers, mask)
    
    # We're gonna use this for the document's @timestamp field
    now = datetime.datetime.utcnow() 
    utctime = now.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % (now.microsecond / 1000) + "Z"
    
    output = {
        'attackers' : global_attackers,
        'cidrs'     : cidrs,
        'avg_reps'  : avg_reps,
        '@timestamp': utctime,
    }   

    today = datetime.date.today().strftime("%Y.%m.%d")
    aggr_index = 'ttp-aggregations-{0}'.format(today)
    doc_type = 'all_raw'

    if not es_client.indices.exists(index=aggr_index):
       userlog.info('Index: {0} does not exist.'.format(aggr_index))
       userlog.info('Creating {0} .'.format(aggr_index))
       es_client.indices.create(aggr_index)
    
    es_client.index(index=aggr_index, doc_type=doc_type, body=output)
    userlog.info('Indexed aggregation document under {0}/{1}'.format(aggr_index, doc_type))

def ddict_to_ldict(ddict):
    """Converts a dictionary of dictionaries to a list of dictionaries"""
    ldict =[]
    for attacker_ip,subdict in ddict.items():
        subdict['attacker_ip'] = attacker_ip
        ldict.append(subdict)
    return ldict

def calculate_avg_reps(es_client, rep_index, district_list):
    """Calculates the average peer reputation"""
    num_districts = district_list['hits']['total']
    
    # Initialize average reputation result dictionary
    res = {district: 0 for district in district_list[0].doc}
    res[district_list[0].meta.doc_type] = 0
    
    # Sum every peer's reputation 
    # and then divide by the group's size to get the average
    for hit in district_list:
        for district in hit.doc:
            res[district] += hit.doc[district]
    for district in res:
        res[district] = int(res[district] / (num_districts-1))
    
    # Push average reputations to Elasticsearch
    avg_doc_type = 'average_rep'
    if not es_client.exists(index=rep_index, doc_type=avg_doc_type, id=1):
        es_client.index(index=rep_index, doc_type=avg_doc_type, id=1, body=res)
    else:
        update_body = { 'doc': res }
        es_client.update(index=rep_index, doc_type=avg_doc_type, id=1, body=update_body)
    return res


def ips_to_cidrs(attackers, mask):
    """Converts a dict of attackers into a list of cidrs""" 
    cidrs={}
    total_attempts = 0
    for attacker in attackers:
        cidr = {}
        ip = ipaddress.ip_address(attacker['attacker_ip'])
        if type(ip) == ipaddress.IPv4Address:
            # Get the /mask network off of the IPv4 address
            network = ipaddress.IPv4Network(ip.exploded+'/'+str(mask), strict=False).exploded
            if network in cidrs:
                cidrs[network]['participants'] += 1

                cidrs[network]['attackers'].append({
                    'attacker_ip'   : attacker['attacker_ip'], 
                    'attempts'      : attacker['attempts'],
                })
                extra_reporters = [
                    reporter for reporter in attacker['reporters'] \
                    if reporter not in cidrs[network]['reporters']
                ]
                cidrs[network]['reporters'] += extra_reporters # Append new reporters    
            else:
                cidrs[network] = {
                'participants': 1, 
                'total_attempts': 0, 
                'attackers':[{
                    'attacker_ip'   : attacker['attacker_ip'], 
                    'attempts'      : attacker['attempts']
                }],
                'reporters': attacker['reporters'],
                }
            cidrs[network]['total_attempts'] += attacker['attempts']
            total_attempts += attacker['attempts']
    # In order to store to Elasticsearch we cannot have IPv4-based fieldnames.
    # Switching to list of cidrs.
    output_cidrs = []
    for cidr,values in cidrs.items():
        values['network'] = cidr
        output_cidrs.append(values)
    return output_cidrs

if __name__ == '__main__':
    all_aggregation()

