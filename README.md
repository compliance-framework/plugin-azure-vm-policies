# Baseline set of Azure VM policies for use in Compliance Framework plugins

## Testing

```shell
opa test policies
```

## Bundling

Policies are built into a bundle to make distribution easier. 

You can easily build the policies by running 
```shell
make build
```

## Running policies locally

You can evaluate a policy using OPA's eval command. For example, to check the Azure VM root volume encryption policy:

```shell
opa eval -I -b policies -f pretty 'data.compliance_framework.unencrypted_root_volume.violation' -d policies/azure_virtual_machines_root_volume_encryption.rego -i <input.json>
```

Replace `<input.json>` with your test input file.

## Writing policies

Policies are written in the [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) language.

Example policy (from this repo):

```rego
package compliance_framework.unencrypted_root_volume

violation[{}] {
  not input.instance.properties.securityProfile.encryptionAtHost
  not input.instance.properties.storageProfile.osDisk.encryptionSettings.enabled
}
```

This policy triggers a violation only if both `encryptionAtHost` and `encryptionSettings.enabled` are false. If `encryptionAtHost` is true, no violation is triggered, regardless of the disk encryption setting.

## Metadata

Plugins expect policies to contain a metadata section as comments, with a `# METADATA` line to indicate it. This metadata should be in a YAML format, and contain a title and description of the policy. Other configuration can be set also, like the schedule that a policy should run on, or the control that it is linked to.

Any other comments can be added as normal (before and after) with a line separator between them and the metadata.

Here is an example metadata:
```opa
# your custom comment

# METADATA
# title: <your-title>
# description: <your-description>
# custom:
#   controls:
#     - <control-id>
#   schedule: "<cron-string>"

# your custom comment
```

---

## License

This project is licensed under the GNU Affero General Public License v3.0. See the [LICENSE](LICENSE) file for details.