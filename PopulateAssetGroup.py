import logging
import sys
import base64
import time
import rapid7vmconsole
from rapid7vmconsole import SearchCriteria, SwaggerSearchCriteriaFilter
from cryptography.fernet import Fernet
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress annoying self-signed cert warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def initialize_api(password):
    config = rapid7vmconsole.Configuration(name='Rapid7')
    config.username = 'apiuser'
    config.password = password
    config.host = ''
    config.verify_ssl = False
    config.assert_hostname = False
    config.proxy = None
    config.ssl_ca_cert = None
    config.connection_pool_maxsize = None
    config.cert_file = None
    config.key_file = None
    config.safe_chars_for_path_param = ''

    # Logging
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)
    config.debug = False

    auth = "%s:%s" % (config.username, config.password)
    auth = base64.b64encode(auth.encode('ascii')).decode()
    client = rapid7vmconsole.ApiClient(configuration=config)
    client.default_headers['Authorization'] = "Basic %s" % auth

    return client

def decrypt_password():
    key = b''
    cipher_suite = Fernet(key)

    with open('rapid7_pass.bin', 'rb') as file_object:
        for line in file_object:
            cipher_text = line
    plain_text  = cipher_suite.decrypt(cipher_text)
    return bytes(plain_text).decode("utf-8")

def get_hosts_from_file(path):
    file = open(path, 'r')
    contents = file.read().splitlines() # avoiding reading newlines

    hosts = []
    for line in contents:
        hosts.append(line)
    return hosts

def get_host_ids(hosts):
    # Initialize timer for status messages
    last_status_time = time.time()

    ids = []
    password = decrypt_password()
    client = initialize_api(password)
    asset_api = rapid7vmconsole.AssetApi(client)

    counter = 0
    for host in hosts:
        # Print status if more than 5 seconds have elapsed since last status
        counter += 1
        if (time.time() - last_status_time > 5):
            print('Processed ' + str(counter) + ' of ' + str(len(hosts)))
            last_status_time = time.time()

        criteria = SwaggerSearchCriteriaFilter(
            field = 'host-name',
            operator = "starts-with",
            value = host
        )
        search_criteria = SearchCriteria(filters=(criteria,), match='all')

        asset_call = asset_api.find_assets(param1=search_criteria)
        if (len(asset_call.resources) == 1):
            ids.append(asset_call.resources[0].id)
    return ids

def clear_assets_from_group(group_id):
    password = decrypt_password()
    client = initialize_api(password)
    asset_group_api = rapid7vmconsole.AssetGroupApi(client)

    asset_group_api.remove_all_assets_from_asset_group(group_id)

def add_assets_to_group(group_id, assets):
    password = decrypt_password()
    client = initialize_api(password)
    asset_group_api = rapid7vmconsole.AssetGroupApi(client)

    asset_group_api.update_asset_group_assets(group_id, assets=assets)

def main():
    hosts = get_hosts_from_file('hosts.csv')
    ids = get_host_ids(hosts)
    print('Found ' + str(len(ids)) + ' of ' + str(len(hosts)))
    clear_assets_from_group('236')
    add_assets_to_group('236', ids)


if __name__ == '__main__':
    main()
