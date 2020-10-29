#!/usr/bin/env bash

VAULT_TOKEN=$(curl \
--silent \
--request POST \
--cert "$HOME/ansible.kansai.pem" \
--key "$HOME/ansible.kansai.key" \
"$VAULT_ADDR/v1/auth/cert/login" | jq -r '.auth.client_token')

SECRET_DATA=$(curl \
--silent \
--request GET \
--header "X-Vault-Token: $VAULT_TOKEN" \
"$VAULT_ADDR/v1/kv/data/ansible" | jq -r '.data.data.secret')

ansible-playbook -K playbooks/common.yml --extra-vars "user_password=$SECRET_DATA user_password_salt=$(sha256sum "$HOME/ansible.kansai.pem" | cut -d ' ' -f 1)"
