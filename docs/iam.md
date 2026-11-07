# IAM and Lake Formation setup

The dashboard only ever runs `SELECT` queries. It needs three things:

1. **IAM permissions** for Athena, Glue (read), the Athena results bucket, and Lake Formation data access.
2. **Lake Formation grants** on the Security Lake database and WAF tables (Security Lake tables are governed by
   Lake Formation, so IAM alone is not enough).
3. A way for the container to obtain credentials for that role (any mechanism, see the bottom of this page).

Placeholders used below: `<ACCOUNT_ID>` (account where Athena runs), `<SECURITY_LAKE_ACCOUNT_ID>` (account that
owns the Security Lake tables, often the same or a log archive account), `<REGION>`, `<ATHENA_RESULTS_BUCKET>`,
`<WORKGROUP>`, `<ROLE_NAME>`.

## 1. IAM permissions policy

Attach to the role the container runs as (or to the role named in `WAF_ASSUME_ROLE_ARN`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AthenaQueries",
      "Effect": "Allow",
      "Action": [
        "athena:StartQueryExecution",
        "athena:GetQueryExecution",
        "athena:GetQueryResults",
        "athena:StopQueryExecution",
        "athena:GetWorkGroup"
      ],
      "Resource": "arn:aws:athena:*:<ACCOUNT_ID>:workgroup/<WORKGROUP>"
    },
    {
      "Sid": "GlueCatalogRead",
      "Effect": "Allow",
      "Action": [
        "glue:GetDatabase",
        "glue:GetDatabases",
        "glue:GetTable",
        "glue:GetTables",
        "glue:GetPartitions"
      ],
      "Resource": [
        "arn:aws:glue:*:<SECURITY_LAKE_ACCOUNT_ID>:catalog",
        "arn:aws:glue:*:<SECURITY_LAKE_ACCOUNT_ID>:database/amazon_security_lake_glue_db_*",
        "arn:aws:glue:*:<SECURITY_LAKE_ACCOUNT_ID>:table/amazon_security_lake_glue_db_*/amazon_security_lake_table_*_waf_*"
      ]
    },
    {
      "Sid": "LakeFormationDataAccess",
      "Effect": "Allow",
      "Action": "lakeformation:GetDataAccess",
      "Resource": "*"
    },
    {
      "Sid": "AthenaResultsBucket",
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:GetObject",
        "s3:PutObject",
        "s3:AbortMultipartUpload"
      ],
      "Resource": [
        "arn:aws:s3:::<ATHENA_RESULTS_BUCKET>",
        "arn:aws:s3:::<ATHENA_RESULTS_BUCKET>/waf-dashboard/*"
      ]
    }
  ]
}
```

Notes:

- `GetDataAccess` lets Athena obtain scoped S3 credentials from Lake Formation, so the role does not need direct
  read access to the Security Lake bucket.
- If you use an Athena workgroup with an enforced output location, the results bucket statement must match it.
- If the results bucket uses a KMS key, add `kms:Encrypt`, `kms:Decrypt`, `kms:GenerateDataKey` for that key.
- Add an explicit deny for every mutating Athena/Glue/S3 action if you want defence in depth. The application never issues them.

## 2. Lake Formation grants

Run as a Lake Formation administrator in the account that owns the Security Lake catalog:

```bash
# Database
aws lakeformation grant-permissions --region <REGION> \
  --principal DataLakePrincipalIdentifier=arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME> \
  --resource '{"Database":{"Name":"amazon_security_lake_glue_db_<REGION_WITH_UNDERSCORES>"}}' \
  --permissions DESCRIBE

# WAF table
aws lakeformation grant-permissions --region <REGION> \
  --principal DataLakePrincipalIdentifier=arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME> \
  --resource '{"Table":{"DatabaseName":"amazon_security_lake_glue_db_<REGION_WITH_UNDERSCORES>","Name":"amazon_security_lake_table_<REGION_WITH_UNDERSCORES>_waf_2_0"}}' \
  --permissions DESCRIBE SELECT
```

Repeat per region listed in `WAF_REGIONS`. For a different principal in another account, use Security Lake's
subscriber access (query access) or Lake Formation cross-account sharing with a resource link in the account
that runs Athena, then point `WAF_SL_DB_TEMPLATE` at the resource-link database. See the Amazon Security Lake
documentation on subscriber query access for the details that apply to your setup.

**Symptom of a missing grant:** Athena returns `TABLE_NOT_FOUND ... does not exist` (and the dashboard shows it
in the credential banner) even though the table exists. Lake Formation hides tables the principal cannot describe.

## 3. Getting credentials into the container

The application calls `boto3.Session(profile_name=WAF_AWS_PROFILE)`; with the profile unset this is the default
chain. Pick the mechanism that fits your host. The role in each case needs the policy above.

### EC2 instance profile

Trust policy for the role:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "ec2.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}
```

Containers reach the instance metadata service through an extra network hop, so allow it:

```bash
aws ec2 modify-instance-metadata-options --region <REGION> --instance-id <INSTANCE_ID> \
  --http-tokens required --http-put-response-hop-limit 2
```

### ECS task role / EKS IRSA / Pod Identity

Use the platform's standard role attachment. Trust policy principal is `ecs-tasks.amazonaws.com` (ECS) or your
cluster's OIDC provider / `pods.eks.amazonaws.com` (EKS). No application setting is required.

### Role in another account (extra hop)

If the Athena role lives in a different account than the host's own role, grant the host role `sts:AssumeRole` on it
and set:

```
WAF_ASSUME_ROLE_ARN=arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME>
WAF_ASSUME_ROLE_EXTERNAL_ID=<EXTERNAL_ID>      # only if the trust policy requires it
```

Trust policy on the target role:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::<HOST_ACCOUNT_ID>:role/<HOST_ROLE_NAME>" },
    "Action": "sts:AssumeRole",
    "Condition": { "StringEquals": { "sts:ExternalId": "<EXTERNAL_ID>" } }
  }]
}
```

Assumed-role credentials are refreshed automatically before they expire.

### Static keys, SSO, IAM Roles Anywhere, anything else

- **Environment variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`.
  Pass them with `docker compose` environment entries or your orchestrator's secret store. Never commit them.
- **Shared config / profiles**: mount the directory and select a profile:

  ```yaml
  # docker-compose.yml
  volumes:
    - ~/.aws:/aws:ro
  environment:
    AWS_CONFIG_FILE: /aws/config
    AWS_SHARED_CREDENTIALS_FILE: /aws/credentials
    WAF_AWS_PROFILE: <PROFILE_NAME>
  ```

  A relocated config file does not relocate the shared credentials file or SSO token cache. The image runs as
  uid 10001, so the directory and selected files must be readable by that uid. Use a dedicated credential
  directory with narrowly scoped file permissions; do not make your entire credential directory world-readable.
  Empty credentials forwarded by Compose do not replace a configured role or profile.

- **SSO profiles**: run `aws sso login --profile <PROFILE_NAME>` on the host first. In addition to the shared
  config mount and file paths above, mount the SSO cache under the container user's home:

  ```yaml
  volumes:
    - ~/.aws:/aws:ro
    - ~/.aws/sso/cache:/home/app/.aws/sso/cache:ro
  environment:
    HOME: /home/app
    AWS_CONFIG_FILE: /aws/config
    AWS_SHARED_CREDENTIALS_FILE: /aws/credentials
    WAF_AWS_PROFILE: <PROFILE_NAME>
  ```

  The cache files must also be readable by uid 10001. A read-only cache cannot persist refreshed login tokens;
  renew the host login when needed. Prefer an instance/task role for unattended service deployments. Do not
  mount credentials or login caches from a production environment into demo/testing containers.

- **IAM Roles Anywhere** (or any tool that issues credentials from an external helper) via `credential_process`:

  ```ini
  [profile <PROFILE_NAME>]
  credential_process = /usr/local/bin/aws_signing_helper credential-process \
    --certificate /certs/cert.pem --private-key /certs/key.pem \
    --trust-anchor-arn <TRUST_ANCHOR_ARN> --profile-arn <PROFILE_ARN> --role-arn <ROLE_ARN>
  region = <REGION>
  ```

  Install the helper in your own image (it is a Linux binary published by AWS) and mount the certificate and key
  read-only. Keep those files out of git (`*.pem` and `*.key` are in `.gitignore`).

## Least-privilege checklist

- [ ] Role limited to one Athena workgroup.
- [ ] Glue read limited to the Security Lake databases and WAF tables.
- [ ] Lake Formation grants limited to `DESCRIBE` on the database and `DESCRIBE`/`SELECT` on the WAF tables.
- [ ] Results bucket write limited to a prefix; lifecycle rule expiring old results.
- [ ] Dashboard reachable only from trusted networks or behind an authenticating proxy.
