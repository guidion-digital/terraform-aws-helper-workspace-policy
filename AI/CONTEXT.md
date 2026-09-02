---
repo: guidion-digital/terraform-aws-helper-workspace-policy
project_name: terraform-aws-helper-workspace-policy
owner: Cinfra
domain: AWS infrastructure authorization
criticality: medium
summary: Terraform module providing AWS workspace policy helpers for API, CDN, container, EC2, and Lambda applications. It centralizes application-specific permissions used by infrastructure workspaces.
main_stack:
  - Terraform
  - AWS
main_systems:
  - API application workspace policies
  - CDN application workspace policies
  - Container application workspace policies
  - EC2 application workspace policies
  - Lambda application workspace policies
last_reviewed: 2026-09-02
review_confidence: medium
generated_by: OpenAI
validated_by: Afraz
---

## Overview

Reusable Terraform module for AWS workspace policies for use by the terraform-tfe-infra-workspaces module. Policy logic is organized by application type in `api_app.tf`, `cdn_app.tf`, `container_app.tf`, `ec2_app.tf`, and `lambda_app.tf`, with shared definitions in `common.tf`.

Automated coverage includes Terraform unit tests under `tests/` and functional tests under `functional-tests/`.

## Purpose and responsibilities

- Define application-specific AWS permissions for infrastructure workspaces.
- Share common policy behavior across supported application types.
- Provide policy variants for API, CDN, container, EC2, and Lambda applications.
- Verify policy behavior with Terraform unit and functional tests.
- Maintain compatibility with the variables supplied by consuming infrastructure workspaces.

## Source of truth / data ownership

The Terraform files in the repository root are the source of truth for generated workspace policy behavior. `common.tf` contains shared policy logic, while the application-specific `*_app.tf` files own permissions for their respective application types.

This repository owns policy definitions, not the AWS resources or application data governed by those policies. Consuming infrastructure workspaces own their Terraform configuration and supply the inputs needed by this module.

## External integrations

- AWS services referenced by the generated IAM policy definitions.
- Terraform consumers, including infrastructure workspaces that use this repository as a module.
- Functional test fixtures under `functional-tests/setup` and `functional-tests/setup2`.

## APIs exposed

No network API is exposed. The repository exposes a Terraform module interface and application-specific policy behavior to consuming Terraform configurations. Consult the root Terraform files and `README.md` for the current inputs and usage.

## APIs / services consumed

- Terraform and the AWS provider.
- AWS IAM policy semantics and the AWS services referenced by each application-specific policy.
- Variables and configuration supplied by consuming infrastructure workspaces.

## Deployment

This repository is a reusable Terraform module rather than a standalone application. Consumers deploy or evaluate its policy definitions as part of their own Terraform workflows.

Unit tests are defined in `tests/unit.tftest.hcl`. Functional tests and their setup configurations are under `functional-tests/`; see `functional-tests/README.md` for the functional-test workflow. Terraform/provider constraints are maintained in `versions.tf`.

## Architectural notes and key decisions

- Policies are separated by workload type to keep permissions scoped to API, CDN, container, EC2, and Lambda use cases.
- Shared Terraform logic belongs in `common.tf`; workload-specific permissions belong in the corresponding `*_app.tf` file.
- Container policy behavior is covered extensively in `tests/unit.tftest.hcl`.
- Container policies include permissions associated with container start, stop, and killed event logging.
- Compatibility must be maintained while newly required variables are being introduced in upstream infrastructure workspaces; recent container-policy changes include a hotfix for variables not yet supplied by those consumers.

## Known risks / fragile areas

- Policy changes can unintentionally broaden or remove AWS permissions. Update and run relevant tests whenever policy statements change.
- The module is coupled to inputs supplied by external infrastructure workspaces. Making an input immediately required can break consumers that have not yet adopted it.
- Event-related container permissions are security-sensitive and should remain narrowly scoped and covered by unit tests.
- Functional tests may require AWS credentials and can create or inspect AWS infrastructure; review their setup before running them.

## AI assistant guidance

- Preserve the separation between shared and application-specific Terraform files.
- Make the smallest policy change that satisfies the requirement; do not broaden actions or resources without explicit justification.
- When changing module inputs, account for consumers that may not yet provide newly introduced variables.
- Update `tests/unit.tftest.hcl` for policy changes and add or adjust functional coverage when behavior cannot be validated adequately by unit tests.
- Review `README.md` when module usage, required inputs, or permissions change.
- Do not infer that similarly named application types require identical permissions.

## Roadmap / active migrations

Infrastructure workspaces are still being aligned with variables expected by recent container policy work. Until those consumers provide the variables consistently, preserve the compatibility behavior introduced by the missing-required-variables hotfix.

No other roadmap is documented in the provided repository state.

## Freshness

This context reflects the current repository structure and the latest provided changes, including container event-log permissions and the compatibility hotfix for variables not yet supplied by infrastructure workspaces. The exact review date and human validation status are unset.
- `last_reviewed`: 2026-09-02
- `generated_by`: CI-generated
