#!/usr/bin/env bash

if [[ -z $1 ]]; then
  echo "Must provide ansible username" >&2
fi

if [[ -z $2 ]]; then
  echo "Must provide ansible hostname" >&2
fi

ssh -t "$1"@"$2" 'cd homelab-ansible && ./run_ansible.sh'
