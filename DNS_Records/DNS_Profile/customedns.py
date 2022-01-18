import requests
import json
import time
import re


def CreateOrUpdateRecord(record_info, params):
    """
    :param record_info:
    :param params:
    :return:
    """
    address = record_info.get(
        'f_ip_address', '') or record_info.get('ip_address', '')
    fqdn = record_info.get('fqdn')
    username = params.get('username')
    passkey = params.get('password')
    ib_host = params.get('host')
    ib_wapi_version = params.get('wapi_version')

    # REST API
    rest_url = 'https://' + ib_host + '/wapi/v' + ib_wapi_version + \
        '/record:host' #+ '?_return_fields=ipv4addrs'
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
            #return r_json['ipv4addrs'][0]['ipv4addr']
        else:
            if 'text' in r_json:
                print("didnt work")
                #raise requests.HTTPError(r_json['text'])
            else:
                r.raise_for_status()
    except ValueError:
        raise Exception(r)
    except Exception:
        raise


def DeleteRecord(record_info, params):
    """
    :param record_info:
    :param params:
    :return:
    """
    fqdn = record_info.get('fqdn')
    username = params.get('username')
    passkey = params.get('password')
    ib_host = params.get('host')
    ib_wapi_version = params.get('wapi_version')

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
