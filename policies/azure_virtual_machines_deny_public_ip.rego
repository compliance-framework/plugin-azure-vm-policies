package compliance_framework.deny_public_ip

violation[{}] if {
	public_ips := [input.network_interfaces[_].public_ips[_].properties.ipAddress]
    some public_ip in public_ips
}

title := "Azure Virtual Machines should not have public IP addresses"
description := "Ensure that Azure Virtual Machines do not have public IP addresses assigned to them. Public IPs can expose VMs to the internet, increasing the risk of unauthorized access and attacks."