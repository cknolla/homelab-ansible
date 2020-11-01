#!/usr/bin/env python3
import json
import logging
import os
from datetime import datetime, timedelta

import requests
import OpenSSL


# set up logging to file - see previous section for more details
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s - %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename='logs/log.log',
                    filemode='w')
# define a Handler which writes INFO messages or higher to the sys.stderr
_console = logging.StreamHandler()
_console.setLevel(logging.INFO)
# set a format which is simpler for console use
_formatter = logging.Formatter('%(levelname)s - %(message)s')
# tell the handler to use this format
_console.setFormatter(_formatter)
# add the handler to the root logger
LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(_console)
LOGGER.info('Loading config file cert_config.json')
with open('cert_config.json') as config_file:
    config = json.load(config_file)
SESSION = requests.Session()


def cert_to_string(cert_path) -> str:
    cert_string = ''
    with open(cert_path) as cert_file:
        for line in cert_file:
            cert_string += line
    return cert_string

def get_vault_token() -> str:
    with SESSION.post(
        f'{config["vault_addr"]}/v1/auth/cert/login',
        cert=(
            f'certs/ansible.{config["domain"]}.pem',
            f'certs/ansible.{config["domain"]}.key',
        ),
    ) as token_response:
        response_data = token_response.json()
        return response_data['auth']['client_token']


def get_needs_renewed(server_name: str, cert_path: str) -> bool:
    try:
        cert_string = cert_to_string(cert_path)
    except FileNotFoundError:
        LOGGER.info(f'No cert found for {server_name}')
        return True  # generate initial cert if none exists
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_string)
    expiration_datetime = datetime.strptime(x509.get_notAfter().decode('utf-8'), r'%Y%m%d%H%M%SZ')
    ttl = expiration_datetime - datetime.utcnow()
    if ttl < timedelta(days=30):
        LOGGER.info(f'{server_name} cert expires in {ttl}. Needs renewal')
        return True
    LOGGER.info(f'{server_name} cert expires in {ttl}. Does not need renewal')
    return False


def fetch_new_cert(server_name: str, output_path: str) -> None:
    key_path = os.path.join(output_path, f'{server_name}.{config["domain"]}.key')
    cert_path = os.path.join(output_path, f'{server_name}.{config["domain"]}.pem')
    with SESSION.post(
        f'{config["vault_addr"]}/v1/pki/issue/kansai',
        json={
            'common_name': f'{server_name}.{config["domain"]}',
            # 'ttl': '3600',
        }
    ) as cert_response:
        cert_response_data = cert_response.json()
        LOGGER.info(f'Generating cert for {server_name} in {output_path}')
        with open(key_path, 'w') as key_file:
            key_file.write(cert_response_data['data']['private_key'])
        os.chmod(key_path, 0o600)
        with open(cert_path, 'w') as pem_file:
            cert_chain = [cert_response_data['data']['certificate']]
            cert_chain.extend(cert_response_data['data']['ca_chain'])
            pem_file.write('\n'.join(cert for cert in cert_chain))
        os.chmod(cert_path, 0o644)
    if server_name == 'ansible':
        LOGGER.info('Updating vault cert for ansible')
        with SESSION.post(
            f'{config["vault_addr"]}/v1/auth/cert/certs/ansible',
            json={
                'display_name': 'ansible',
                'token_policies': 'ansible,cert-create',
                'certificate': cert_to_string(os.path.join(output_path, f'{server_name}.{config["domain"]}.pem')),
                'token_ttl': '3600',
            }
        ) as ansible_cert_response:
            if ansible_cert_response.status_code != 204:
                LOGGER.error(f'Error updating ansible cert in vault!: {ansible_cert_response.json()}')
            else:
                LOGGER.info(f'Successfully refreshed ansible cert for TLS auth in vault')


def main():
    vault_token = None
    for server_name, output_path in config['servers'].items():
        LOGGER.info(f'Checking if {server_name} cert needs renewed')
        if get_needs_renewed(server_name, os.path.join(output_path, f'{server_name}.{config["domain"]}.pem')):
            if vault_token is None:
                SESSION.verify = f'roles/common/files/{config["ca_name"]}'
                LOGGER.info('Fetching vault token')
                vault_token = get_vault_token()
                SESSION.headers = {
                    'X-Vault-Token': vault_token,
                }
            LOGGER.info(f'Fetching new cert for {server_name}')
            fetch_new_cert(server_name, output_path)


if __name__ == '__main__':
    main()

