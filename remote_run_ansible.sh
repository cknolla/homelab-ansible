#!/usr/bin/env bash

# useful for setting up in an IDE's run configuration

if [[ -z $1 ]]; then
  echo "Must provide ansible username" >&2
  exit
fi

if [[ -z $2 ]]; then
  echo "Must provide ansible hostname" >&2
  exit
fi

if [[ -z $3 ]]; then
  echo "Must provide remote working directory" >&2
  exit
fi

ssh -t "$1"@"$2" "cd $3 && ./run_ansible.sh"
