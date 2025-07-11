package compliance_framework.deny_public_ip

test_violation_with_public_ip if {
    count(violation) == 1 with input as {
        "instance": {
            "id": "/subscriptions/620b2384-447c-4d3d-8f66-200f3ebb241b/resourceGroups/TEST-1234/providers/Microsoft.Compute/virtualMachines/test-1",
            "location": "eastus"
        },
        "network_interfaces": [
            {
                "config": {},
                "public_ips": [
                    {
                        "properties": {
                            "ipAddress": "1.1.1.1"
                        }
                    }
                ]
            }
        ]
    }
}

test_no_violation_without_public_ip if {
    count(violation) == 0 with input as {
        "instance": {
            "id": "/subscriptions/620b2384-447c-4d3d-8f66-200f3ebb241b/resourceGroups/TEST-1234/providers/Microsoft.Compute/virtualMachines/test-1",
            "location": "eastus"
        },
        "network_interfaces": [
            {
                "config": {},
                "public_ips": []
            }
        ]
    }
}
