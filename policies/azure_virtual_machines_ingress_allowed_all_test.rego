package compliance_framework.ingress_allowed_all

test_no_violation_with_default_security_group if {
    count(violation) == 0 with input as {
        "instance": {
            "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ccf/providers/Microsoft.Compute/virtualMachines/vm-compliant",
            "location": "uksouth",
            "name": "vm-uncompliant",
        },
        "network_interfaces": [
            {
                "config": {
                },
                "security_group": {
                    "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ccf/providers/Microsoft.Network/networkSecurityGroups/sg-ssh-inbound",
                    "location": "uksouth",
                    "name": "sg-ssh-inbound",
                    "properties": {
                        "defaultSecurityRules": [
                            {
                                "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ccf/providers/Microsoft.Network/networkSecurityGroups/sg-ssh-inbound/defaultSecurityRules/DenyAllInBound",
                                "name": "DenyAllInBound",
                                "properties": {
                                    "access": "Deny",
                                    "description": "Deny all inbound traffic",
                                    "destinationAddressPrefix": "*",
                                    "destinationAddressPrefixes": [],
                                    "destinationPortRange": "*",
                                    "destinationPortRanges": [],
                                    "direction": "Inbound",
                                    "priority": 65500,
                                    "protocol": "*",
                                    "provisioningState": "Succeeded",
                                    "sourceAddressPrefix": "*",
                                    "sourceAddressPrefixes": [],
                                    "sourcePortRange": "*",
                                    "sourcePortRanges": []
                                },
                                "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules",
                                "etag": "W/\"ff3d80b2-c3f2-435b-8954-50c49a3670e9\""
                            }
                        ],
                        "networkInterfaces": [
                            {
                                "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/RG-CCF/providers/Microsoft.Network/networkInterfaces/NIC-VM-COMPLIANT"
                            }
                        ],
                        "provisioningState": "Succeeded",
                        "resourceGuid": "79c0f017-83de-4576-ae50-e8b8ba6c39a3",
                        "securityRules": [
                        ]
                    },
                    "tags": {},
                    "type": "Microsoft.Network/networkSecurityGroups"
                }
            }
        ]
    }
}

test_violation_with_open_inbound_custom_rule if {
    count(violation) > 0 with input as {
        "instance": {
            "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ccf/providers/Microsoft.Compute/virtualMachines/vm-compliant",
            "location": "uksouth",
            "name": "vm-uncompliant",
        },
        "network_interfaces": [
            {
                "config": {
                },
                "security_group": {
                    "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ccf/providers/Microsoft.Network/networkSecurityGroups/sg-ssh-inbound",
                    "location": "uksouth",
                    "name": "sg-ssh-inbound",
                    "properties": {
                        "defaultSecurityRules": [
                            {
                                "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ccf/providers/Microsoft.Network/networkSecurityGroups/sg-ssh-inbound/defaultSecurityRules/DenyAllInBound",
                                "name": "DenyAllInBound",
                                "properties": {
                                    "access": "Deny",
                                    "description": "Deny all inbound traffic",
                                    "destinationAddressPrefix": "*",
                                    "destinationAddressPrefixes": [],
                                    "destinationPortRange": "*",
                                    "destinationPortRanges": [],
                                    "direction": "Inbound",
                                    "priority": 65500,
                                    "protocol": "*",
                                    "provisioningState": "Succeeded",
                                    "sourceAddressPrefix": "*",
                                    "sourceAddressPrefixes": [],
                                    "sourcePortRange": "*",
                                    "sourcePortRanges": []
                                },
                                "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules",
                                "etag": "W/\"ff3d80b2-c3f2-435b-8954-50c49a3670e9\""
                            }
                        ],
                        "networkInterfaces": [
                            {
                                "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/RG-CCF/providers/Microsoft.Network/networkInterfaces/NIC-VM-COMPLIANT"
                            }
                        ],
                        "provisioningState": "Succeeded",
                        "resourceGuid": "79c0f017-83de-4576-ae50-e8b8ba6c39a3",
                        "securityRules": [
                            {
                                "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ccf/providers/Microsoft.Network/networkSecurityGroups/sg-ssh-inbound/securityRules/Allow-All-Inbound",
                                "name": "Allow-All-Inbound",
                                "properties": {
                                    "access": "Allow",
                                    "destinationAddressPrefix": "*",
                                    "destinationAddressPrefixes": [],
                                    "destinationPortRange": "*",
                                    "destinationPortRanges": [],
                                    "direction": "Inbound",
                                    "priority": 101,
                                    "protocol": "*",
                                    "provisioningState": "Succeeded",
                                    "sourceAddressPrefix": "*",
                                    "sourceAddressPrefixes": [],
                                    "sourcePortRange": "*",
                                    "sourcePortRanges": []
                                },
                                "type": "Microsoft.Network/networkSecurityGroups/securityRules",
                                "etag": "W/\"ff3d80b2-c3f2-435b-8954-50c49a3670e9\""
                            }
                        ]
                    },
                    "tags": {},
                    "type": "Microsoft.Network/networkSecurityGroups"
                }
            }
        ]
    }
}

test_no_violation_with_mutltiple_priorities if {
    count(violation) == 0 with input as {
        "instance": {
            "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ccf/providers/Microsoft.Compute/virtualMachines/vm-compliant",
            "location": "uksouth",
            "name": "vm-uncompliant",
        },
        "network_interfaces": [
            {
                "config": {
                },
                "security_group": {
                    "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ccf/providers/Microsoft.Network/networkSecurityGroups/sg-ssh-inbound",
                    "location": "uksouth",
                    "name": "sg-ssh-inbound",
                    "properties": {
                        "defaultSecurityRules": [
                            {
                                "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ccf/providers/Microsoft.Network/networkSecurityGroups/sg-ssh-inbound/defaultSecurityRules/DenyAllInBound",
                                "name": "DenyAllInBound",
                                "properties": {
                                    "access": "Deny",
                                    "description": "Deny all inbound traffic",
                                    "destinationAddressPrefix": "*",
                                    "destinationAddressPrefixes": [],
                                    "destinationPortRange": "*",
                                    "destinationPortRanges": [],
                                    "direction": "Inbound",
                                    "priority": 65500,
                                    "protocol": "*",
                                    "provisioningState": "Succeeded",
                                    "sourceAddressPrefix": "*",
                                    "sourceAddressPrefixes": [],
                                    "sourcePortRange": "*",
                                    "sourcePortRanges": []
                                },
                                "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules",
                                "etag": "W/\"ff3d80b2-c3f2-435b-8954-50c49a3670e9\""
                            }
                        ],
                        "networkInterfaces": [
                            {
                                "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/RG-CCF/providers/Microsoft.Network/networkInterfaces/NIC-VM-COMPLIANT"
                            }
                        ],
                        "provisioningState": "Succeeded",
                        "resourceGuid": "79c0f017-83de-4576-ae50-e8b8ba6c39a3",
                        "securityRules": [
                            {
                                "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ccf/providers/Microsoft.Network/networkSecurityGroups/sg-ssh-inbound/securityRules/Allow-All-Inbound",
                                "name": "Allow-All-Inbound",
                                "properties": {
                                    "access": "Allow",
                                    "destinationAddressPrefix": "*",
                                    "destinationAddressPrefixes": [],
                                    "destinationPortRange": "*",
                                    "destinationPortRanges": [],
                                    "direction": "Inbound",
                                    "priority": 101,
                                    "protocol": "*",
                                    "provisioningState": "Succeeded",
                                    "sourceAddressPrefix": "*",
                                    "sourceAddressPrefixes": [],
                                    "sourcePortRange": "*",
                                    "sourcePortRanges": []
                                },
                                "type": "Microsoft.Network/networkSecurityGroups/securityRules",
                                "etag": "W/\"ff3d80b2-c3f2-435b-8954-50c49a3670e9\""
                            },
                            {
                                "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ccf/providers/Microsoft.Network/networkSecurityGroups/sg-ssh-inbound/securityRules/Deny-All-Inbound-1",
                                "name": "Deny-All-Inbound-1",
                                "properties": {
                                    "access": "Deny",
                                    "destinationAddressPrefix": "*",
                                    "destinationAddressPrefixes": [],
                                    "destinationPortRange": "*",
                                    "destinationPortRanges": [],
                                    "direction": "Inbound",
                                    "priority": 1,
                                    "protocol": "*",
                                    "provisioningState": "Succeeded",
                                    "sourceAddressPrefix": "*",
                                    "sourceAddressPrefixes": [],
                                    "sourcePortRange": "*",
                                    "sourcePortRanges": []
                                },
                                "type": "Microsoft.Network/networkSecurityGroups/securityRules",
                                "etag": "W/\"ff3d80b2-c3f2-435b-8954-50c49a3670e9\""
                            }
                        ]
                    },
                    "tags": {},
                    "type": "Microsoft.Network/networkSecurityGroups"
                }
                
            }
        ]
    }
}