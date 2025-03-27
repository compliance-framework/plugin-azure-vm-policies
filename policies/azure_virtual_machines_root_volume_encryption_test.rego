package compliance_framework.template.azure_virtual_machines._deny_unencrypted_root_volume

test_violation_unencrypted_root_volume if {
  violation[violation_item] with input as {
    "Name": "test-1",
    "Properties": {
      "diskDetails": {
        "azureDiskEncryption": false
      }
    }
  }

  violation_item.title == "Root volume is not encrypted"
}