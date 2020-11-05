build:
	go build -o vault/plugins/vault-plugin-secrets-terraform cmd/vault-plugin-secrets-terraform/main.go

server:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins