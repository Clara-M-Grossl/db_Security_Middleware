#!/bin/sh

echo "Waiting for vault to start..."
while ! vault status > /dev/null 2>&1; do
  nc -z vault 8200
  if [ $? -eq 0 ]; then
    break
  fi
  sleep 2
done

INIT_STATUS=$(vault status -format=json | grep -o '"initialized": *\(true\|false\)' | cut -d: -f2 | tr -d ' ')

if [ "$INIT_STATUS" = "false" ]; then
  echo "Vault nao incializado, inicializando...."
  vault operator init -key-shares=1 -key-threshold=1 -format=json > /vault/file/init.json
  echo "Vault inicializado, chaves salvas"
else
  echo "Vault já esta inicializadp"
fi

UNSEAL_KEY=$(grep -A 1 '"unseal_keys_b64":' /vault/file/init.json | tail -n 1 | cut -d'"' -f2)
ROOT_TOKEN=$(grep '"root_token":' /vault/file/init.json | cut -d'"' -f4)

echo "Unsealing Vault..."
vault operator unseal $UNSEAL_KEY

export VAULT_TOKEN=$ROOT_TOKEN
vault login $ROOT_TOKEN

vault secrets enable -path=secret kv-v2 || true

echo "Vault Setup feito"
