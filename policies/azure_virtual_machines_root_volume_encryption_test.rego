package compliance_framework.unencrypted_root_volume

test_falsy_data if {
  count(violation) > 0 with input as {
    "instance": {
     "id": "/subscriptions/a0911991-bf92-4bee-bf87-0578e1c4810b/resourceGroups/CCF-DEMO_GROUP/providers/Microsoft.Compute/virtualMachines/test-1",
     "location": "eastus",
     "name": "test-1",
     "properties": {
       "securityProfile": {
         "encryptionAtHost": false,
       },
       "storageProfile": {
         "osDisk": {
           "encryptionSettings": {
               "enabled": false
           },
         }
       },
     }
   }
  }
}

test_empty_data if {
  count(violation) > 0 with input as {
    "instance": {
     "id": "/subscriptions/a0911991-bf92-4bee-bf87-0578e1c4810b/resourceGroups/CCF-DEMO_GROUP/providers/Microsoft.Compute/virtualMachines/test-1",
     "location": "eastus",
     "name": "test-1",
     "properties": {
       "securityProfile": {
       },
       "storageProfile": {
         "osDisk": {
         }
       },
     }
   }
  }
}

test_host_encryption if {
  count(violation) == 0 with input as {
    "instance": {
     "id": "/subscriptions/a0911991-bf92-4bee-bf87-0578e1c4810b/resourceGroups/CCF-DEMO_GROUP/providers/Microsoft.Compute/virtualMachines/test-1",
     "location": "eastus",
     "name": "test-1",
     "properties": {
       "securityProfile": {
         "encryptionAtHost": true,
       },
       "storageProfile": {
         "osDisk": {
           "encryptionSettings": {
               "enabled": false
           },
         }
       },
     }
   }
  }
}

test_disk_encryption if {
  count(violation) == 0 with input as {
    "instance": {
     "id": "/subscriptions/a0911991-bf92-4bee-bf87-0578e1c4810b/resourceGroups/CCF-DEMO_GROUP/providers/Microsoft.Compute/virtualMachines/test-1",
     "location": "eastus",
     "name": "test-1",
     "properties": {
       "securityProfile": {
         "encryptionAtHost": false,
       },
       "storageProfile": {
         "osDisk": {
           "encryptionSettings": {
               "enabled": true
           },
         }
       },
     }
   }
  }
}

test_managed_disk_encryption if {
  count(violation) == 0 with input as {
    "instance": {
     "id": "/subscriptions/a0911991-bf92-4bee-bf87-0578e1c4810b/resourceGroups/CCF-DEMO_GROUP/providers/Microsoft.Compute/virtualMachines/test-1",
     "location": "eastus",
     "name": "test-1",
     "properties": {
       "securityProfile": {
         "encryptionAtHost": false,
       },
       "storageProfile": {
         "osDisk": {
          "managedDisk": {
            "diskEncryptionSet": {
              "id": "/subscriptions/a0911991-bf92-4bee-bf87-0578e1c4810b/resourceGroups/CCF-DEMO_GROUP/providers/Microsoft.Compute/diskEncryptionSets/test-disk-encryption-set"
            }
           },
         }
       },
     }
   }
  }
}