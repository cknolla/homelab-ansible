#!/usr/bin/env python3
import json
import logging
import os
import sys
from datetime import datetime, timedelta

import requests
import OpenSSL


def get_vault_token() -> str:
    with session.post(
        f'{config["vault_addr"]}/v1/auth/cert/login',
        cert=(
            f'certs/ansible.{config["domain"]}.pem',
            f'certs/ansible.{config["domain"]}.key',
        ),
    ) as token_response:
        response_data = token_response.json()
        return response_data['auth']['client_token']


def get_needs_renewed(cert_path: str) -> bool:
    cert_string = ''
    try:
        with open(cert_path) as cert_file:
            for line in cert_file:
                cert_string += line
    except FileNotFoundError:
        print(f'No cert found for {server_name}')
        return True  # generate initial cert if none exists
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_string)
    expiration_datetime = datetime.strptime(x509.get_notAfter().decode('utf-8'), r'%Y%m%d%H%M%SZ')
    ttl = expiration_datetime - datetime.utcnow()
    if ttl < timedelta(days=30):
        print(f'{server_name} cert expires in {ttl}. Needs renewal')
        return True
    print(f'{server_name} cert expires in {ttl}. Does not need renewal')
    return False


def fetch_new_cert(server_name: str, output_path: str) -> None:
    with session.post(
        f'{config["vault_addr"]}/v1/pki/issue/kansai',
        json={
            'common_name': f'{server_name}.{config["domain"]}',
            # 'ttl': '3600',
        }
    ) as cert_response:
        cert_response_data = cert_response.json()
        print(f'Generating cert for {server_name} in {output_path}')
        with open(os.path.join(output_path, f'{server_name}.{config["domain"]}.key'), 'w') as key_file:
            key_file.write(cert_response_data['data']['private_key'])
        with open(os.path.join(output_path, f'{server_name}.{config["domain"]}.pem'), 'w') as pem_file:
            cert_chain = [cert_response_data['data']['certificate']]
            cert_chain.extend(cert_response_data['data']['ca_chain'])
            pem_file.write('\n'.join(cert for cert in cert_chain))
    if server_name == 'ansible':
        print('Updating vault cert for ansible')
        with session.post(
            f'{config["vault_addr"]}/v1/auth/cert/certs/ansible',
            json={
                'display_name': 'ansible',
                'token_policies': 'ansible,cert-create',
                'certificate': os.path.join(output_path, f'{server_name}.{config["domain"]}.pem'),
                'token_ttl': '3600',
            }
        ) as ansible_cert_response:
            if ansible_cert_response.status_code != 201:
                print('Error updating ansible cert in vault!')


if __name__ == '__main__':
    # logging.basicConfig()
    # logger = logging.getLogger(__name__)
    # logger.addHandler(logging.StreamHandler(sys.stdout))
    print('Loading config file cert_config.json')
    with open('cert_config.json') as config_file:
        config = json.load(config_file)
    session = requests.Session()
    session.verify = f'certs/{config["ca_name"]}'
    print('Fetching vault token')
    vault_token = get_vault_token()
    session.headers = {
        'X-Vault-Token': vault_token,
    }
    for server_name, output_path in config['servers'].items():
        print(f'Checking if {server_name} cert needs renewed')
        if get_needs_renewed(os.path.join(output_path, f'{server_name}.{config["domain"]}.pem')):
            print(f'Fetching new cert for {server_name}')
            fetch_new_cert(server_name, output_path)