package compliance_framework.template.azure_virtual_machines._deny_public_ip

test_violation_with_public_ip if {
    count(violation) == 1 with input as {
        "name": "test-1",
        "InstanceID": "vm-12345",
        "properties": {
            "networkProfile": {
                "networkInterfaces": [
                    {
                        "properties": {
                            "ipConfigurations": [
                                {
                                    "properties": {
                                        "publicIPAddress": "203.0.113.0"
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }
    }
}

test_no_violation_without_public_ip if {
    count(violation) == 0 with input as {
        "name": "test-1",
        "InstanceID": "vm-12345",
        "properties": {
            "networkProfile": {
                "networkInterfaces": [
                    {
                        "properties": {
                            "ipConfigurations": [
                                {
                                    "properties": {
                                        "publicIPAddress": null
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }
    }
}
