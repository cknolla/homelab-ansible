# Purpose
To automate the configuration of homelab servers

# Overview
1. Using `cert_renewal.py`, check for and renew server certs if less than threshold days till expiration via vault intermediate CA
1. Bootstrap freshly made servers to be accessible by ansible
1. Perform a set of common tasks that all servers should have
    - Create `casey` user and inject client pubkeys
    - Copy in profile files such as `.bash_aliases`
    - `apt update` and `apt upgrade-dist`
    - Install common packages
    - Copy homelab root CA and make it locally trusted
1. Install and configure nginx on proxy machine
    - For each proxy destination:
        - Copy site config
        - Copy cert
        - Enable site config
    -  Disable default config
1. Install and configure apache servers
    - Similar to proxy playbook, but configure server per-host rather than via proxy
    
# Pre-requisites
- Root CA must be generated
- Vault must be configured on the network as an intermediate CA
- Ansible cert and key must be stored in `certs/ansible.{{ domain }}.pem` and `certs/ansible.{{ domain }}.key` respectively.
Domain and other cert renewal config can be done in `cert_config.json`

# Usage
1. `apt install ansible`
1. `apt install python3-venv`
1. `python3 -m venv venv` at root project directory
1. `source venv/bin/activate`
1. `pip install -r requirements.txt`
1. `deactivate`
1. `./run_ansible.sh playbooks/homelab.yml` on ansible host

## Add proxy destinations
1. Add an entry to `server_certs` within `cert_config.json` with output to `roles/proxy/files`
1. Add an entry to `sites` within `roles/proxy/defaults/main.yml`
1. Add alias to DNS Resolver

# Logging
Logs are saved to `logs/`
    
