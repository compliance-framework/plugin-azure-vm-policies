package compliance_framework.template.azure_virtual_machines._deny_public_ip

test_violation_with_public_ip if {
    count(violation) == 1 with input as {
        "Name": "test-1",
        "VMID": "/subscriptions/620b2384-447c-4d3d-8f66-200f3ebb241b/resourceGroups/TEST-1234/providers/Microsoft.Compute/virtualMachines/test-1",
        "Properties": {
            "networkDetails": {
                "publicIPAddress": "172.187.249.127"
            }
        }
    }
}

test_no_violation_without_public_ip if {
    count(violation) == 0 with input as {
        "Name": "test-1",
        "VMID": "/subscriptions/620b2384-447c-4d3d-8f66-200f3ebb241b/resourceGroups/TEST-1234/providers/Microsoft.Compute/virtualMachines/test-1",
        "Properties": {
            "networkDetails": {
                "publicIPAddress": null
            }
        }
    }
}
