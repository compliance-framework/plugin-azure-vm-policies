package compliance_framework.template.azure_virtual_machines._deny_unencrypted_root_volume

test_violation_unencrypted_root_volume if {
  violation[violation_item] with input as {
    "name": "test-1",
    "properties": {
      "storageProfile": {
        "osDisk": {
          "encryptionSettings": {
            "enabled": false
          }
        }
      }
    }
  }

  violation_item.title == "Root volume is not encrypted"
}