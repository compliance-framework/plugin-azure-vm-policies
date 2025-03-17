package compliance_framework.template.azure_virtual_machines._deny_unencrypted_root_volume

violation[{
  "title": "Root volume is not encrypted",
  "description": sprintf("VM '%v' has an unencrypted root volume.", [input.name]),
  "remarks": "Ensure the root volume of the Azure VM is encrypted."
}] if {
  some os_disk in input.properties.storageProfile.osDisk
  not os_disk.encryptionSettings.enabled
}
