package compliance_framework.deny_default_security_groups

test_violation_with_default_security_group if {
    count(violation) == 1 with input as {
        "instance": {
            "id": "/subscriptions/620b2384-447c-4d3d-8f66-200f3ebb241b/resourceGroups/TEST-1234/providers/Microsoft.Compute/virtualMachines/test-1",
            "location": "eastus"
        },
        "network_interfaces": [
            {
                "config": {},
                "security_group": {
                    "properties": {
                        "defaultSecurityRules": [
                            {
                                "name": "default-rule-1",
                                "properties": {
                                    "priority": 100,
                                    "access": "Allow",
                                    "direction": "Inbound",
                                    "protocol": "*",
                                    "sourcePortRange": "*",
                                    "destinationPortRange": "*",
                                    "sourceAddressPrefix": "*",
                                    "destinationAddressPrefix": "*"
                                }
                            }
                        ]
                    }
                }
            }
        ]
    }
}

test_violation_with_no_default_security_group if {
    count(violation) == 0 with input as {
        "instance": {
            "id": "/subscriptions/620b2384-447c-4d3d-8f66-200f3ebb241b/resourceGroups/TEST-1234/providers/Microsoft.Compute/virtualMachines/test-1",
            "location": "eastus"
        },
        "network_interfaces": [
            {
                "config": {},
                "security_group": {
                    "properties": {
                        "defaultSecurityRules": [
                        ]
                    }
                }
            }
        ]
    }
}

test_violation_with_multiple_sg_one_default_security_group if {
    count(violation) == 1 with input as {
        "instance": {
            "id": "/subscriptions/620b2384-447c-4d3d-8f66-200f3ebb241b/resourceGroups/TEST-1234/providers/Microsoft.Compute/virtualMachines/test-1",
            "location": "eastus"
        },
        "network_interfaces": [
            {
                "config": {},
                "security_group": {
                    "properties": {
                        "defaultSecurityRules": [
                        ]
                    }
                }
            },
            {
                "config": {},
                "security_group": {
                    "properties": {
                        "defaultSecurityRules": [
                            {
                                "name": "default-rule-1",
                                "properties": {
                                    "priority": 100,
                                    "access": "Allow",
                                    "direction": "Inbound",
                                    "protocol": "*",
                                    "sourcePortRange": "*",
                                    "destinationPortRange": "*",
                                    "sourceAddressPrefix": "*",
                                    "destinationAddressPrefix": "*"
                                }
                            }
                        ]
                    }
                }
            }
        ]
    }
}
