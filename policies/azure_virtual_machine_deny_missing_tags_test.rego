package compliance_framework.deny_missing_tags

test_violation_with_missing_tags if {
    count(violation) == 1 with input as {
        "instance": {
            "name": "test-instance",
            "tags": {
                "name": "test-instance",
                "environment": "prod",
            }
        }
    }
}

test_no_violation_with_all_tags if {
    count(violation) == 0 with input as {
        "instance": {
            "name": "test-instance",
            "tags": {
                "name": "test-instance",
                "environment": "prod",
                "security": "high",
                "compliance": "yes",
                "application": "app1",
                "cost center": "cc1",
                "project": "project1",
                "owner": "owner1"
            }
        }
    }
}

test_no_violation_with_all_regardless_of_case if {
    count(violation) == 0 with input as {
        "instance": {
            "name": "test-instance",
            "tags": {
                "NAME": "test-instance",
                "Environment": "prod",
                "sEcUrItY": "high",
                "CoMpLiAnCe": "yes",
                "application": "app1",
                "cost center": "cc1",
                "project": "project1",
                "owner": "owner1"
            }
        }
    }
}