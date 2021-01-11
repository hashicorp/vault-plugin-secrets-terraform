# HashiCorp Vault Terraform Secrets Engine

The Terraform Secrets Engine is a plugin for HashiCorp Vault which generates
dynamic [API tokens](https://www.terraform.io/docs/cloud/users-teams-organizations/api-tokens.html)
for Terraform Cloud or Enterprise.

> The [Golang SDK for Terraform Cloud / Enterprise](https://github.com/hashicorp/go-tfe)
> does not support the generation
> of user API tokens at this time.

## Usage

1. Enable secrets engine.
   ```shell
   vault secrets enable -path=terraform vault-plugin-secrets-terraform
   ```

1. Write the configuration with a Terraform Cloud or Enterprise token.
   ```shell
   vault write terraform/config token=$TF_TOKEN
   ```
   If you are using Terraform Enterprise, you can specify the `address` and `base_path`.

1. You can create two types of tokens: an organization token or a team token.

   1. To create an organization token, create a Vault role with the Terraform organization.
      ```shell
      vault write terraform/role/my-org organization=$TF_ORGANIZATION
      ```

   1. To create a team token, create a Vault role with the Terraform organization and
      ID of the team (find using the `settings/teams/team-xxxxxxxxxx` URL).
      ```shell
      vault write terraform/role/my-team organization=$TF_ORGANIZATION team_id=$TF_TEAM_ID
      ```

1. To read the token, access the `creds` endpoint.
   ```shell
   $ vault read terraform/creds/my-org

   Key                Value
   ---                -----
   lease_id           terraform/creds/my-org/HZ8edrojluU1fzVy7GWoIUpo
   lease_duration     768h
   lease_renewable    true
   token              TERRAFORM_CLOUD_OR_ENTERPRISE_TOKEN
   ```

## Support, Bugs and Feature Requests

Bugs should be filed under the Issues section of this repo.

Feature requests can be submitted in the Issues section.

## Quick Links
- [Terraform Secrets Engine - API Docs](https://www.terraform.io/docs/cloud/users-teams-organizations/api-tokens.html)
- [Vault Website](https://www.vaultproject.io)

**Please note**: Hashicorp takes Vault's security and their users' trust very seriously, as does MongoDB.

If you believe you have found a security issue in Vault, _please responsibly disclose_ by
contacting HashiCorp at [security@hashicorp.com](mailto:security@hashicorp.com).

## Running tests

To run the unit tests, you can execute:

```bash
$ go test .
```

To run the acceptance tests, you need to set the following environment variables:

```bash
VAULT_ACC=1
TF_TOKEN=<Terraform Cloud or Enterprise Token with Organization Access>
TF_ORGANIZATION=<Terraform Cloud or Enterprise Organization>
TF_TEAM_ID=<Terraform Cloud or Enterprise Team ID from `settings/teams/team-xxxxxxxxxxxx`>
```

The API key provided must be an organization owner. You can manage access through the
[Terraform Cloud or Enteprise UI](https://www.terraform.io/docs/cloud/users-teams-organizations/teams.html#the-owners-team).