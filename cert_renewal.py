#!/usr/bin/env python3
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime, timedelta

import requests
import OpenSSL


# set up logging to console and a rotating logfile
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    handlers=[
                        RotatingFileHandler(
                            f'logs/{__file__}.log',
                            maxBytes=5000000,
                            backupCount=5,
                            encoding='utf-8',
                        ),
                        logging.StreamHandler(),
                    ])
LOGGER = logging.getLogger(__name__)
LOGGER.info('Loading config file cert_config.json')
with open('cert_config.json') as config_file:
    config = json.load(config_file)
if config['testing']:
    LOGGER.warning(f'Testing mode is enabled')
SESSION = requests.Session()


def cert_to_string(cert_path) -> str:
    with open(cert_path) as cert_file:
        cert_string = ''.join(line for line in cert_file)
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


def refresh_vault_cert(server_name: str, output_path: str) -> None:
    LOGGER.info(f'Updating vault cert for {server_name}')
    with SESSION.post(
            f'{config["vault_addr"]}/v1/auth/cert/certs/{server_name}',
            json={
                'display_name': server_name,
                'certificate': cert_to_string(os.path.join(output_path, f'{server_name}.{config["domain"]}.pem')),
                'token_policies': [
                    server_name,
                    'cert-create',
                ],
                'token_ttl': '3600',
            }
    ) as vault_cert_refresh_response:
        if vault_cert_refresh_response.status_code != 204:
            LOGGER.error(f'Error updating {server_name} cert in vault!\n{vault_cert_refresh_response.json()}')
        else:
            LOGGER.info(f'Successfully refreshed {server_name} cert for TLS auth in vault')


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
    LOGGER.info(f'Skipping {server_name}. Cert expires in {ttl}.')
    return False


def fetch_new_cert(server_name: str, output_path: str) -> None:
    key_path = os.path.join(output_path, f'{server_name}.{config["domain"]}.key')
    cert_path = os.path.join(output_path, f'{server_name}.{config["domain"]}.pem')
    payload = {
        'common_name': f'{server_name}.{config["domain"]}',
    }
    if config['testing']:
        payload['ttl'] = '3600'  # make a short-lived cert
    with SESSION.post(
        f'{config["vault_addr"]}/v1/pki/issue/{config["domain"]}',
        json=payload,
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
        refresh_vault_cert(server_name, output_path)


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

