#!/usr/bin/env bash

if [[ -z $1 ]]; then
    PLAYBOOK="playbooks/homelab.yml"
  else
    PLAYBOOK=$1
fi

DOMAIN=$(cat < "cert_config.json" | jq -r '.domain')
VAULT_ADDR=$(cat < "cert_config.json" | jq -r '.vault_addr')

# renew certs with python script
source venv/bin/activate && ./cert_renewal.py && deactivate

VAULT_TOKEN=$(curl \
--silent \
--request POST \
--cert "certs/ansible.$DOMAIN.pem" \
--key "certs/ansible.$DOMAIN.key" \
"$VAULT_ADDR/v1/auth/cert/login" | jq -r '.auth.client_token')

SECRET_DATA=$(curl \
--silent \
--request GET \
--header "X-Vault-Token: $VAULT_TOKEN" \
"$VAULT_ADDR/v1/kv/data/ansible/user/casey" | jq -r '.data.data.password')

ansible-playbook \
-e user_password="$SECRET_DATA" \
-e user_password_salt="$(sha256sum "certs/ansible.$DOMAIN.key" | cut -d ' ' -f 1)" \
"$PLAYBOOK"


