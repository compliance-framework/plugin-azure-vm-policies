package compliance_framework.template.azure_virtual_machines._deny_default_sg

violation[{
    "title": "Azure VM is using the default security group",
    "description": sprintf("VM '%v' is using the default security group", [input.name]),
    "remarks": "Ensure Azure VMs are not using the default security group. Define custom security groups with appropriate rules."
}] if {
    some network_interface in input.properties.networkProfile.networkInterfaces
    some ip_configuration in network_interface.properties.ipConfigurations
    ip_configuration.properties.networkSecurityGroup.properties.securityRules[_].name == "default"
}