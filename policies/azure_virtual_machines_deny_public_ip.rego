package compliance_framework.template.azure_virtual_machines._deny_public_ip

violation[{
    "title": "Check to ensure Azure VM does not have a public IP",
    "description": sprintf("VM '%v' (%v) has a public IP address, which is not allowed.", [input.Name, input.VMID]),
    "remarks": "Ensure the Azure VM does not have a public IP address."
}] if {
    input.Properties.networkDetails.publicIPAddress != null
}