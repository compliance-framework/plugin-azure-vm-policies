package compliance_framework.template.azure_virtual_machines._deny_default_sg

violation[{
    "title": "Azure VM is using the default security group",
    "description": sprintf("VM '%v' is using the default security group", [input.Name]),
    "remarks": "Ensure Azure VMs are not using the default security group. Define custom security groups with appropriate rules."
}] if {
    some rule in input.Properties.networkDetails.securityGroup.rules
    rule.name == "default"
}