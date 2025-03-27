package compliance_framework.template.azure_virtual_machines._deny_default_sg

test_violation_with_default_security_group if {
    violation[violation_item] with input as {
        "Name": "test-1",
        "Properties": {
            "networkDetails": {
                "securityGroup": {
                    "rules": [
                        {"name": "default"}
                    ]
                }
            }
        }
    }

    violation_item.title == "Azure VM is using the default security group"
}
