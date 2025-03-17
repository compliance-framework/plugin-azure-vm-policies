package compliance_framework.template.azure_virtual_machines._deny_public_ip

violation[{
    "title": "Check to ensure Azure VM does not have a public IP",
    "description": sprintf("VM '%v' (%v) has a public IP address, which is not allowed.", [input.name, input.InstanceID]),
    "remarks": "Ensure the Azure VM does not have a public IP address."
}] if {
    some network_interface in input.properties.networkProfile.networkInterfaces
    some ip_configuration in network_interface.properties.ipConfigurations
    ip_configuration.properties.publicIPAddress != null
}