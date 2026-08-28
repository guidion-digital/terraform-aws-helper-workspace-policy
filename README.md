Part of the [Terrappy framework](https://github.com/guidion-digital/terrappy).

---

Small helper module which generates least-privilage policies necessary for application modules to be able to create their resources.

# Rationale

The permissions needed by the Terrappy application modules in order to create their necessary resources are known. For this reason, we template them (by type) here, and use this helper module to create consistent IAM policies for use with application modules.

We do not create the IAM user here, since we also want to use this with the pretend [S3 Workspaces](https://github.com/GuidionOps/terraform-aws-infra-s3-workspaces/) module (which does not need an IAM user created for it).

# Usage

See the [examples folder](./examples), and bear in mind that it doubles as a test. Read the [README](./examples/test_app/README.md) in there for details on how that works.

In most cases, it is expected for the client code (the [S3 workspace](https://github.com/GuidionOps/terraform-aws-infra-s3-workspaces/) and [TFE workspace](https://github.com/guidion-digital/terraform-tfe-infra-workspaces) modules) to provide full resource ARNs to add permissions for. For example, when creating a policy for the [container application module](https://github.com/GuidionOps/terraform-module-aws-ecs-fargate-container), you specify:

```hcl
...

  container_app = {
    targetgroup_arn : string,
    loadbalancers : list(string),
    loadbalancer_listener_arn : string,
    ecs_cluster_arn : string,
    ecs_service_arn : string,
    ecs_event_capture_rule_arn : string,
    ecs_event_capture_log_group_arn : string
  }

...
```

in order to create permissions for a limited set of targetgroups, loadbalancers, etc.

The ARNs are worked out in the workspace modules ([S3 workspace](https://github.com/GuidionOps/terraform-aws-infra-s3-workspaces/) and [TFE workspace](https://github.com/guidion-digital/terraform-tfe-infra-workspaces) from which this module is called.

The `container_app` policy also includes the Terraform permissions required to
manage ECS lifecycle event capture through EventBridge and CloudWatch Logs.
Those permissions are for the Terraform workspace principal; they are not
permissions for the ECS task role. EventBridge rule actions are scoped to the
forwarded `container_app.ecs_event_capture_rule_arn`, and the new log-group
tagging actions are scoped to the forwarded event log group ARN. These fields
are optional for backwards compatibility with older TFE workspace modules; the
event-capture statements are omitted when they are not supplied.
The account-level CloudWatch Logs resource-policy actions remain scoped to `*`
because those APIs do not support resource ARNs.
