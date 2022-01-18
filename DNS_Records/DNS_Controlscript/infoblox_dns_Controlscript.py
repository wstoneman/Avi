#!/usr/bin/python

import sys
import os
import json
import traceback
import requests
import re
from avi.sdk.avi_api import ApiSession


def parse_avi_params(argv):
    if len(argv) != 2:
        return {}
    script_parms = json.loads(argv[1])
    return script_parms


def create_avi_endpoint():
    token = os.environ.get('API_TOKEN')
    user = os.environ.get('USER')
    # tenant=os.environ.get('TENANT')
    return ApiSession.get_session("localhost", user, token=token,
                                  tenant='admin')


def dns_entry(session, script_parms):
    vs_uuid = script_parms['events'][0]['obj_uuid']
    vs_name = script_parms['events'][0]['event_details']['se_hm_vs_details']['virtual_service']
    event = script_parms['events'][0]['event_id']

    username = <infoblox user>
    passkey = <infoblox password>
    ib_host = <infoblox ip>
    ib_wapi_version = "1.2"

    print(('Event uuid %s %s' % (vs_name, str(script_parms))))
    if len(script_parms['events']) == 0:
        print('WARNING: No events in alert')
        return

    if event == "VS_DOWN":
        reason = script_parms['events'][0]['event_details']['se_hm_vs_details']['reason']
        if reason == "Virtual Service disabled by user":
            rsp = session.get('virtualservice?uuid=%s' % vs_uuid)

            if rsp.status_code in range(200, 299):
                for vsObj in rsp.json()['results']:
                    # print(vsObj)

                    address = vsObj['ip_address']['addr']
                    fqdn = vsObj['dns_info'][0]['fqdn']
                    fqdn = fqdn.lower()

                    # REST API
                    rest_url = 'https://' + ib_host + '/wapi/v' + ib_wapi_version + \
                               '/record:host?name=' + fqdn + '&view=default'
                    try:
                        r = requests.get(url=rest_url,
                                         auth=(username, passkey),
                                         verify=False)
                        r_json = r.json()
                        if r.status_code == 200:
                            if len(r_json) > 0:
                                host_ref = r_json[0]['_ref']
                                if host_ref and re.match("record:host\/[^:]+:([^\/]+)\/", host_ref).group(1) == fqdn:
                                    rest_url = 'https://' + ib_host + '/wapi/v' + ib_wapi_version + '/' + host_ref
                                    r = requests.delete(url=rest_url,
                                                        auth=(username, passkey),
                                                        verify=False)
                                    if r.status_code == 200:
                                        return
                                    else:
                                        if 'text' in r_json:
                                            raise requests.HTTPError(r_json['text'])
                                        else:
                                            r.raise_for_status()
                                else:
                                    raise requests.HTTPError(
                                        "No network reference received in IBA reply for network: " + fqdn)
                            else:
                                raise requests.HTTPError("No network found: " + fqdn)
                        else:
                            if 'text' in r_json:
                                raise requests.HTTPError(r_json['text'])
                            else:
                                r.raise_for_status()
                    except ValueError:
                        raise Exception(r)
                    except Exception:
                        raise



    elif event == "VS_UP":
        rsp = session.get('virtualservice?uuid=%s' % vs_uuid)

        if rsp.status_code in range(200, 299):
            for vsObj in rsp.json()['results']:
                # print(vsObj)

                address = vsObj['ip_address']['addr']
                fqdn = vsObj['dns_info'][0]['fqdn']
                fqdn = fqdn.lower()

    # REST API
    rest_url = 'https://' + ib_host + '/wapi/v' + ib_wapi_version + \
               '/record:host'  # + '?_return_fields=ipv4addrs'
    payload = '{"ipv4addrs": [{"configure_for_dhcp": false,"ipv4addr": "' + \
              address + '"}],"name": "' + fqdn + '","view": "default"}'
    try:
        r = requests.post(url=rest_url,
                          auth=(username, passkey),
                          verify=False, data=payload)
        r_json = r.json()
        print(r_json)
        if r.status_code == 200 or r.status_code == 201:
            print("worked")
            # return r_json['ipv4addrs'][0]['ipv4addr']
        else:
            if 'text' in r_json:
                print("didnt work")
                # raise requests.HTTPError(r_json['text'])
            else:
                r.raise_for_status()
    except ValueError:
        raise Exception(r)
    except Exception:
        raise
    # Script entry


if __name__ == "__main__":
    script_parms = parse_avi_params(sys.argv)
    try:
        admin_session = create_avi_endpoint()
        dns_entry(admin_session, script_parms)
    except Exception:
        print(('WARNING: Exception with Infoblox %s' %
               traceback.format_exc()))