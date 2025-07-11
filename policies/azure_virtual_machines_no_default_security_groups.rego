package compliance_framework.deny_default_security_groups

violation[{}] if {
	security_groups := [input.network_interfaces[_].security_group]
	every sg in security_groups {
    	some _ in sg.properties.defaultSecurityRules
    }
}

title := "Azure Virtual Machines should not use default security groups"
description := "Ensure that Azure Virtual Machines do not use default security groups. Using custom security groups allows for more granular control over network traffic and enhances security by avoiding the broad permissions often associated with default security groups."