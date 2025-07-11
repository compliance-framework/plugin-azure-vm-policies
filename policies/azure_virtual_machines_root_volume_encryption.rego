package compliance_framework.unencrypted_root_volume

violation[{}] if {
	not input.instance.properties.securityProfile.encryptionAtHost
  not input.instance.properties.storageProfile.osDisk.managedDisk.diskEncryptionSet.id
	not input.instance.properties.storageProfile.osDisk.encryptionSettings.enabled
}


title := "Azure Virtual Machines Root Volume Encryption should be enabled"
description := "Ensure that the root volume of Azure Virtual Machines is encrypted to protect sensitive data. A violation is triggered if host encryption is not enabled, managed disk does not have a disk encryption set, or the OS disk doesn't have encryption settings enabled."