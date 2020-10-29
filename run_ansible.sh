#!/usr/bin/env bash

VAULT_TOKEN=$(curl \
--request POST \
--cert "$HOME/ansible.kansai.pem" \
--key "$HOME/ansible.kansai.key" \
"$VAULT_ADDR/v1/auth/cert/login" | jq -r '.auth.client_token')

SECRET_DATA=$(curl \
--request GET \
--header "X-Vault-Token: $VAULT_TOKEN" \
"$VAULT_ADDR/v1/kv/data/ansible" | jq -r '.data.data.secret')

echo "$SECRET_DATA"
