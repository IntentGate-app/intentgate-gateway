# IntentGate deployment artifacts

Operator-facing files for deploying and integrating IntentGate. Each
subdirectory is platform-specific; all files are safe to copy and
adapt to your environment.

## Layout

| Directory | Contents |
|---|---|
| `aws/` | S3 lifecycle policy, IAM policy for the gateway's pod identity |
| `athena/` | Glue catalog DDL for the IntentGate audit table |
| `kql/` | Microsoft Sentinel KQL queries for the SOC dashboard |

## Cross-reference

The `/docs/integrations/aws-sentinel` page on
[intentgate.app](https://intentgate.app/docs/integrations/aws-sentinel)
is the prose walkthrough that ties these artifacts together. This
directory holds the actual files you `apply`, `import`, or `aws
configure`.

## Stability

Files here track the gateway's audit event schema. The Athena DDL and
the KQL queries assume the gateway's default field mapping and are
maintained by hand, so review them when `audit.Event` changes. Breaking
schema changes are called out in release notes.
