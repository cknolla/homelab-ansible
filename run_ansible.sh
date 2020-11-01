#!/usr/bin/env bash

if [[ -z $1 ]]; then
  echo "Must provide path to playbook" >&2
fi

PLAYBOOK=$1

#VAULT_TOKEN=$(curl \
#--silent \
#--request POST \
#--cert "$HOME/ansible.kansai.pem" \
#--key "$HOME/ansible.kansai.key" \
#"$VAULT_ADDR/v1/auth/cert/login" | jq -r '.auth.client_token')
#
#SECRET_DATA=$(curl \
#--silent \
#--request GET \
#--header "X-Vault-Token: $VAULT_TOKEN" \
#"$VAULT_ADDR/v1/kv/data/ansible/user/casey" | jq -r '.data.data.password')
#
#ansible-playbook \
#-e user_password="$SECRET_DATA" \
#-e user_password_salt="$(sha256sum "$HOME/ansible.kansai.pem" | cut -d ' ' -f 1)" \
#"$PLAYBOOK"


