
# Switch a VS from vsphere cloud to NSX-T Cloud on a remote Avi Cluster
# Written by William Stoneman wstoneman@vmware.com & Shawn Watson wshawn@vmware.com
# python3 switch_cloud_vs_final.py -c <Source controller IP/name> -u admin -p <password> -c2 <Destination controller IP/name> -u2 admin -p2 <password> -a <API version> -v <vs csv list> -nv <network conversion csv list> -q <Target Cloud name>

import json
import time
import argparse
import csv
import re
from avi.sdk.avi_api import ApiSession
from requests.packages import urllib3
from getpass import getpass

urllib3.disable_warnings()

### Global Variables
## --------------------------

REF_NAME_MATCH = '^.*\/api\/(\w+)(.*)#(.*)$'
REF_KEY_MATCH = '^.*_ref$'
REFS_KEY_MATCH = '^.*_refs$'
arg = {}
INFRA_EXCLUDE_CLONE = ['se_group_ref', 'cloud_ref', 'tenant_ref', 'vrf_context_ref', 'vrf_ref', 'vsvip_ref', 'pool_ref', 'pool_group_ref', 'network_ref']
REMOVE_OBJ_LIST = ['uuid', '_last_modified', 'url', 'vip_runtime', 'hs_security_tls13_score', 'vs_refs', 'tls_ticket_key']


### /Global Variables
## /--------------------------

### Main
## --------------------------

def main():
    # Getting Required Args
    parser = argparse.ArgumentParser(description="AVISDK based Script to migrate VSs between Clouds and Clusters")
    parser.add_argument("-u", "--username", required=True, help="Login Source username")
    parser.add_argument("-p", "--password", required=True, action='store_true', dest='password', help="Login Source password")
    parser.add_argument("-c", "--controller", required=True, help="Source Controller IP address")
    parser.add_argument("-u2", "--username2", required=True, help="Login Destination username")
    parser.add_argument("-p2", "--password2", required=True, action='store_true', dest='password2', help="Login Destination password")
    parser.add_argument("-c2", "--controller2", required=True, help="Destination Controller IP address")
    parser.add_argument("-a", "--api_version", required=False, help="Api Version")
    parser.add_argument("-v", "--vs_csv", required=True, help="VS csv name")
    parser.add_argument("-nv", "--net_csv", required=True, help="Network Conversion csv name")
    parser.add_argument("-q", "--target_cloud", required=True, help="Target Cloud name")
    parser.add_argument("-d", "--delay", required=False, help="Delay between enable operations in seconds")
    args = parser.parse_args()
    user = args.username
    host = args.controller
    #password = args.password
    if args.password:
        password = getpass("Please enter source Avi password: ")

    user2 = args.username2
    host2 = args.controller2
    #password2 = args.password2
    if args.password2:
        password2 = getpass("Please enter destination Avi password: ")

    vs_csv = args.vs_csv
    net_csv = args.net_csv
    cloud_ref = args.target_cloud
    arg["cloud_ref"] = cloud_ref
    if args.delay:
        delay = args.delay
    else:
        delay = 2
    if args.api_version:
        api_version = args.api_version
    else:
        api_version = "20.1.6"

### /Main
## /--------------------------

    ### Function Definition
    ## --------------------------

    # Create pool
    def create_pool(obj):
        placement_net = []
        vs_pool_name = obj.split('#')[1]
        pool_rsp = source_api.get('tenant/%s/pool?name=%s' % (source_tenantObj['results'][0]['uuid'], vs_pool_name),
                                  params={"include_name": "true"})
        pool_data = pool_rsp.json()['results'][0]
        if "networks" in pool_data:
            pool_data.pop('networks')
        for server in pool_data['servers']:
            if "discovered_networks" in server:
                for networks in server['discovered_networks']:
                    for subnet in networks['subnet']:
                        net_file.seek(0)
                        for net_row in networkreader:
                            if subnet['ip_addr']['addr'] == net_row['source_net'] and subnet['mask'] == int(
                                    net_row['source_mask']):
                                for net_network in network_obj['results']:
                                    if "configured_subnets" in net_network:
                                        for net_subnets in net_network['configured_subnets']:
                                            if net_subnets['prefix']['ip_addr']['addr'] == net_row[
                                                'destination_net'] and net_subnets['prefix']['mask'] == int(
                                                net_row['destination_mask']):
                                                placementObj = {}
                                                placementObj['subnet'] = net_subnets['prefix']
                                                placementObj['network_ref'] = net_network['url']
                                                if placement_net:
                                                    for net in placement_net:
                                                        if net['subnet']['ip_addr']['addr'] == \
                                                                net_subnets['prefix']['ip_addr']['addr']:
                                                            pass
                                                        else:
                                                            placement_net.append(placementObj)
                                                else:
                                                    placement_net.append(placementObj)
                                                pool_data['placement_networks'] = placement_net
                                                server.pop('discovered_networks')

        pooloutput = clean_up(pool_data)


        f.write("---------------------------------\n")
        f.write("POOL\n")
        f.write("---------------------------------\n")
        f.write("POOL Policies\n")
        f.write("---------------------------------\n")

        for k, v in pooloutput.items():
            if k not in INFRA_EXCLUDE_CLONE:
                checkRef(k, v)

        f.write("---------------------------------\n")

        buildNewObj("pool", pooloutput)

        f.write("---------------------------------\n")

    def create_poolgroup(obj):
        vs_pool_group_name = obj.split('#')[1]
        vs_pool_group_obj = source_api.get('tenant/%s/poolgroup?name=%s' % (source_tenantObj['results'][0]['uuid'], vs_pool_group_name),api_version=api_version, params={"include_name": "true"})
        vs_pool_group_obj = vs_pool_group_obj.json()['results'][0]
        vs_pool_obj = []
        for pool in vs_pool_group_obj['members']:
            pool_name = pool['pool_ref'].split('#')[1]
            pool_obj = source_api.get('tenant/%s/pool?name=%s' % (source_tenantObj['results'][0]['uuid'], pool_name),api_version=api_version, params={"include_name": "true"})
            pool_obj = pool_obj.json()['results'][0]
            vs_pool_obj.append(pool_obj)


        for pool in vs_pool_obj:
            placement_net = []
            pool_rsp = source_api.get('tenant/%s/pool/%s' % (source_tenantObj['results'][0]['uuid'], pool['uuid']),
                                      api_version=api_version, params={"include_name": "true"})
            pool_data = pool_rsp.json()
            if "networks" in pool_data:
                pool_data.pop('networks')
            for server in pool_data['servers']:
                if "discovered_networks" in server:
                    for networks in server['discovered_networks']:
                        for subnet in networks['subnet']:
                            net_file.seek(0)
                            for net_row in networkreader:
                                if subnet['ip_addr']['addr'] == net_row['source_net'] and subnet['mask'] == int(
                                        net_row['source_mask']):
                                    for net_network in network_obj['results']:
                                        if "configured_subnets" in net_network:
                                            for net_subnets in net_network['configured_subnets']:
                                                if net_subnets['prefix']['ip_addr']['addr'] == net_row[
                                                    'destination_net'] and net_subnets['prefix']['mask'] == int(
                                                    net_row['destination_mask']):
                                                    placementObj = {}
                                                    placementObj['subnet'] = net_subnets['prefix']
                                                    placementObj['network_ref'] = net_network['url']
                                                    if placement_net:
                                                        for net in placement_net:
                                                            if net['subnet']['ip_addr']['addr'] == \
                                                                    net_subnets['prefix']['ip_addr']['addr']:
                                                                pass
                                                            else:
                                                                placement_net.append(placementObj)
                                                    else:
                                                        placement_net.append(placementObj)
                                                    pool_data['placement_networks'] = placement_net
                                                    server.pop('discovered_networks')


            pooloutput = clean_up(pool_data)


            f.write("---------------------------------\n")
            f.write("POOL GROUP\n")
            f.write("---------------------------------\n")
            f.write("POOL GROUP - POOLS\n")
            f.write("---------------------------------\n")

            for k, v in pooloutput.items():
                if k not in INFRA_EXCLUDE_CLONE:
                    checkRef(k, v)

            f.write("---------------------------------\n")

            buildNewObj("pool", pooloutput)

            f.write("---------------------------------\n")

        # Convert Pool Group
        pg_rsp = source_api.get(
            'tenant/%s/poolgroup?name=%s' % (source_tenantObj['results'][0]['uuid'], vs_pool_group_name),
            api_version=api_version, params={"include_name": "true"})
        poolgroup_data = pg_rsp.json()['results'][0]


        poolgroupoutput = clean_up(poolgroup_data)


        for k, v in poolgroupoutput.items():
            if k not in INFRA_EXCLUDE_CLONE:
                checkRef(k, v)

        buildNewObj("poolgroup", poolgroupoutput)

        f.write("---------------------------------\n")

    # Cleanup immutable/state objects in Dict
    def clean_up(obj):
        for i in REMOVE_OBJ_LIST:
            if i in obj: obj.pop(i)
        return (obj)

    # Dynamically iterate through every object in Dict
    # To determine if any nested references are found
    def traverse_obj(obj, path=None):
        if path is None:
            path = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if re.match(REF_KEY_MATCH, k):
                    checkRef(k, v)
        elif isinstance(obj, list):
            return [traverse_obj(elem, path + [[]]) for elem in obj]

    # Reference checks and actions
    def checkRef(k, v):
        if re.match(REF_KEY_MATCH, k):
            match = re.match(REF_NAME_MATCH, v)
            if match and k not in INFRA_EXCLUDE_CLONE:
                obj_search = source_api.get(match.group(1) + match.group(2), params={"include_name": "true"})
                obj_dict = json.loads(obj_search.text)
                traverse_obj(obj_dict)
                old_obj = clean_up(obj_dict)
                buildNewObj(match.group(1), old_obj)
        elif re.match(REFS_KEY_MATCH, k):
            for value in v:
                match = re.match(REF_NAME_MATCH, value)
                if match and k not in INFRA_EXCLUDE_CLONE:
                    obj_search = source_api.get(match.group(1) + match.group(2), params={"include_name": "true"})
                    obj_dict = json.loads(obj_search.text)
                    traverse_obj(obj_dict)
                    old_obj = clean_up(obj_dict)
                    buildNewObj(match.group(1), old_obj)
        elif not isinstance(v, str):
            traverse_obj(v)

    def buildNewObj(obj_type, obj):
        for k, v in obj.items():
            # Update references
            if re.match("http_request_policy", k):
                for value in v['rules']:
                    if "switching_action" in value:
                        if "pool_ref" in value['switching_action']:
                            create_pool(value['switching_action']['pool_ref'])
                            match = re.match(REF_NAME_MATCH, value['switching_action']['pool_ref'])
                            value['switching_action']['pool_ref'] = "/api/%s?name=%s" % (match.group(1), match.group(3))
                        elif "pool_group_ref" in value['switching_action']:
                            create_poolgroup(value['switching_action']['pool_group_ref'])
                            match = re.match(REF_NAME_MATCH, value['switching_action']['pool_group_ref'])
                            value['switching_action']['pool_group_ref'] = "/api/%s?name=%s" % (match.group(1), match.group(3))
            elif re.match(REF_KEY_MATCH, k):
                match = re.match(REF_NAME_MATCH, v)
                obj[k] = "/api/%s?name=%s" % (match.group(1), match.group(3))
            elif re.match(REFS_KEY_MATCH, k):
                array = []
                for value in v:
                    match = re.match(REF_NAME_MATCH, value)
                    array.append("/api/%s?name=%s" % (match.group(1), match.group(3)))
                obj[k] = array
            elif re.match("members", k):
                for value in v:
                    if "pool_ref" in value:
                        match = re.match(REF_NAME_MATCH, value['pool_ref'])
                        value['pool_ref'] = "/api/%s?name=%s" % (match.group(1), match.group(3))
            elif re.match("content_rewrite", k):
                if "rewritable_content_ref" in v:
                    match = re.match(REF_NAME_MATCH, v['rewritable_content_ref'])
                    v['rewritable_content_ref'] = "/api/%s?name=%s" % (match.group(1), match.group(3))
            elif re.match("http_policies", k):
                for value in v:
                    if "http_policy_set_ref" in value:
                        match = re.match(REF_NAME_MATCH, value['http_policy_set_ref'])
                        value['http_policy_set_ref'] = "/api/%s?name=%s" % (match.group(1), match.group(3))
            elif re.match("vs_datascripts", k):
                for value in v:
                    if "vs_datascript_set_ref" in value:
                        match = re.match(REF_NAME_MATCH, value['vs_datascript_set_ref'])
                        value['vs_datascript_set_ref'] = "/api/%s?name=%s" % (match.group(1), match.group(3))
            elif re.match("https_monitor", k):
                if "ssl_attributes" in v:
                    match = re.match(REF_NAME_MATCH, v['ssl_attributes']['ssl_profile_ref'])
                    v['ssl_attributes']['ssl_profile_ref'] = "/api/%s?name=%s" % (match.group(1), match.group(3))
            # Update values based on arguments passed (example: cloud_ref name change)
            if k in arg:
                obj[k] = obj[k].split("=")[0] + '=' + arg[k]
        #if obj_type == "applicationprofile":
            #print(obj['name'])
        print('Recreating Object - %s' % obj_type)
        f.write('Recreating Object - %s' % obj_type + '\n')
        create = destination_api.post(obj_type, json.dumps(obj), tenant=obj['tenant_ref'].split("=")[1],timeout=120)
        if obj_type == "analyticsprofile" and create.reason == "CREATED":
            output_array['analyticsprofile'] = create.reason
        elif obj_type == "analyticsprofile" and create.reason != "CREATED":
            output_array['analyticsprofile'] = (json.loads(create.text)['error'])
        if obj_type == "applicationprofile" and create.reason == "CREATED":
            output_array['applicationprofile'] = create.reason
        elif obj_type == "applicationprofile" and create.reason != "CREATED":
            output_array['applicationprofile'] = json.loads(create.text)['error']
        if obj_type == "stringgroup" and create.reason == "CREATED":
            output_array['rewritable'] = create.reason
        elif obj_type == "stringgroup" and create.reason != "CREATED":
            output_array['rewritable'] = json.loads(create.text)['error']
        if obj_type == "httppolicyset" and create.reason == "CREATED":
            output_array['httppolicyset'] = create.reason
        elif obj_type == "httppolicyset" and create.reason != "CREATED":
            output_array['httppolicyset'] = json.loads(create.text)['error']
        if obj_type == "networkprofile" and create.reason == "CREATED":
            output_array['networkprofile'] = create.reason
        elif obj_type == "networkprofile" and create.reason != "CREATED":
            output_array['networkprofile'] = json.loads(create.text)['error']
        if obj_type == "networksecuritypolicy" and create.reason == "CREATED":
            output_array['networksecuritypolicy'] = create.reason
        elif obj_type == "networksecuritypolicy" and create.reason != "CREATED":
            output_array['networksecuritypolicy'] = json.loads(create.text)['error']
        if obj_type == "healthmonitor" and create.reason == "CREATED":
            healthmonitor_array.append(create.reason)
            output_array['healthmonitor'] = healthmonitor_array
        elif obj_type == "healthmonitor" and create.reason != "CREATED":
            healthmonitor_array.append(json.loads(create.text)['error'])
            output_array['healthmonitor'] = healthmonitor_array
        if obj_type == "sslprofile" and create.reason == "CREATED":
            output_array['sslprofile'] = create.reason
        elif obj_type == "sslprofile" and create.reason != "CREATED":
            output_array['sslprofile'] = json.loads(create.text)['error']
        if obj_type == "pool" and create.reason == "CREATED":
            pool_array.append(create.reason)
            output_array['pool'] = pool_array
        elif obj_type == "pool" and create.reason != "CREATED":
            pool_array.append(json.loads(create.text)['error'])
            output_array['pool'] = pool_array
        if obj_type == "poolgroup" and create.reason == "CREATED":
            output_array['poolgroup'] = create.reason
        elif obj_type == "poolgroup" and create.reason != "CREATED":
            output_array['poolgroup'] = json.loads(create.text)['error']
        if obj_type == "vsvip" and create.reason == "CREATED":
            output_array['vsvip'] = create.reason
        elif obj_type == "vsvip" and create.reason != "CREATED":
            output_array['vsvip'] = json.loads(create.text)['error']
        if obj_type == "virtualservice" and create.reason == "CREATED":
            output_array['virtualservice'] = create.reason
        elif obj_type == "virtualservice" and create.reason != "CREATED":
            output_array['virtualservice'] = json.loads(create.text)['error']

        if create.reason != "CREATED":
            print("CONFLICT: " + json.loads(create.text)['error'])
            f.write("CONFLICT: " + json.loads(create.text)['error'] + '\n')
        else:
            print(create.reason)
            f.write(create.reason + '\n')

    ### /Function Definition
    ## /--------------------------


    ### API Session Definition
    ## --------------------------


    # Old Controller
    source_api = ApiSession.get_session(host, user, password, api_version=api_version, tenant='*')

    # New Controller
    destination_api = ApiSession.get_session(host2, user2, password2, api_version=api_version, tenant='*')

    ### /API Session Definition
    ## /--------------------------

    ### Create Output File
    ## --------------------------

    # Create output File
    #file = open('vs_output.csv', 'w')

    with open('vs_output.csv', 'w') as outfile, open('output_log.txt', 'a') as f:

    #with file:
        fnames = ['vs_name', 'analyticsprofile', 'applicationprofile', 'rewritable', 'httppolicyset', 'networkprofile',
                  'networksecuritypolicy', 'healthmonitor', 'pool', 'sslprofile', 'poolgroup', 'vsvip', 'virtualservice']
        writer = csv.DictWriter(outfile, fieldnames=fnames)

        writer.writeheader()


    ### /Create Output File
    ## /--------------------------

        ### Import CSV
        ## --------------------------

        # Import CSV File
        file = open(vs_csv)
        csvreader = csv.DictReader(file)

        net_file = open(net_csv)
        networkreader = csv.DictReader(net_file)

        for row in csvreader:

            output_array = {}
            healthmonitor_array = []
            pool_array = []

        ### /Import CSV
        ## /--------------------------

            ### Get VS Definition
            ## --------------------------

            # Get Source VS

            vs_source_obj = source_api.get("virtualservice", params={"name": row['vs_name'], "include_name": "true"})
            # to dict and clean up
            for vsObj in vs_source_obj.json()['results']:
                vsObj = clean_up(vsObj)
                output_array['vs_name'] = vsObj['name']

                f.write(vsObj['name'] + '\n')
                f.write("####################################\n")

                #print(vsObj)

                ### /Get VS Definition
                ## /--------------------------


                ### Get Source and Tenant Object
                ## --------------------------

                # Get VS Tenant UUID
                source_tenant_name = vsObj['tenant_ref'].split('#')[1]
                source_tenantObj = source_api.get('tenant?name=%s' % source_tenant_name)
                source_tenantObj = source_tenantObj.json()

                destination_tenantObj = destination_api.get('tenant?name=%s' % source_tenant_name)
                destination_tenantObj = destination_tenantObj.json()

                ### /Get Source and Tenant Object
                ## /--------------------------


                ### Get VS VIP Object
                ## --------------------------

                # Get VS VIP Name
                source_vip_ref = vsObj['vsvip_ref'].split('#')[1]
                # print(source_vip_ref)

                # Retrieve VS VIP Object
                vs_vip_obj = source_api.get('tenant/%s/vsvip?name=%s' % (source_tenantObj['results'][0]['uuid'], source_vip_ref),params={"include_name": "true"})
                vs_vip_obj = vs_vip_obj.json()['results'][0]
                vs_vip_obj = clean_up(vs_vip_obj)

                # Get Source VS VIP subnet address
                source_vip_network = vs_vip_obj['vip'][0]['discovered_networks'][0]['subnet'][0]['ip_addr']['addr']

                ### /Get VS VIP Object
                ## /--------------------------

                ### Get Destination Network Information
                ## --------------------------

                # Get all Networks
                network_obj = destination_api.get('network?cloud_ref.name=%s' % cloud_ref,
                                                  params={"include_name": "true"})
                network_obj = network_obj.json()


                ### /Get Destination Network Information
                ## /--------------------------


                ### Create Pool and Pool Group
                ## --------------------------

                # Convert Pool Object

                if "pool_ref" in vsObj:
                    create_pool(vsObj['pool_ref'])


                elif "pool_group_ref" in vsObj:
                    create_poolgroup(vsObj['pool_group_ref'])


                ### /Create Pool and Pool Group
                ## /--------------------------


                ### Create VS VIP
                ## --------------------------

                ## Convert VSVIP
                for vip in vs_vip_obj['vip']:
                    if "discovered_networks" in vip:
                        for networks in vip['discovered_networks']:
                            for subnet in networks['subnet']:
                                net_file.seek(0)
                                for net_row in networkreader:
                                    if subnet['ip_addr']['addr'] == net_row['source_net'] and subnet['mask'] == int(
                                            net_row['source_mask']):
                                        for net_network in network_obj['results']:
                                            if "configured_subnets" in net_network:
                                                for net_subnets in net_network['configured_subnets']:
                                                    if net_subnets['prefix']['ip_addr']['addr'] == net_row[
                                                        'destination_net'] and net_subnets['prefix']['mask'] == int(
                                                            net_row['destination_mask']):
                                                        vip_placement_net = []
                                                        vip_placementObj = {}
                                                        vip_placementObj['subnet'] = net_subnets['prefix']
                                                        vip_placementObj['network_ref'] = net_network['url']
                                                        vip_placement_net.append(vip_placementObj)
                                                        vip['placement_networks'] = vip_placement_net

                        vip.pop('discovered_networks')


                vsvipoutput = clean_up(vs_vip_obj)


                f.write("---------------------------------\n")
                f.write("VS VIP\n")
                f.write("---------------------------------\n")
                f.write("VS VIP Policies\n")
                f.write("---------------------------------\n")

                for k, v in vsvipoutput.items():
                    if k not in INFRA_EXCLUDE_CLONE:
                        checkRef(k, v)

                f.write("---------------------------------\n")

                buildNewObj("vsvip", vsvipoutput)

                f.write("---------------------------------\n")


                ### /Create VS VIP
                ## /--------------------------

                ### Create Profiles and Policies
                ## --------------------------

                f.write("Profiles and Policies\n")
                f.write("---------------------------------\n")
                for k, v in vsObj.items():
                    if k not in INFRA_EXCLUDE_CLONE:
                        checkRef(k, v)

                ### /Create Profiles and Policies
                ## /--------------------------

                ### Create VS
                ## --------------------------

                ## Convert VS
                vsObj['enabled'] = False
                vsObj['cloud_type'] = "CLOUD_NSXT"


                f.write("---------------------------------\n")
                f.write("VS OBJECT\n")
                f.write("---------------------------------\n")

                buildNewObj("virtualservice", vsObj)

                f.write("---------------------------------\n")

               ### /Create VS
               ## /--------------------------

                f.write("####################################\n")
                f.write("\n")
                f.write("\n")
                f.write("\n")

                writer.writerow(output_array)

if __name__ == "__main__":
    main()


