package compliance_framework.deny_missing_tags

required_tags := ["Environment", "Security", "Compliance", "Application", "Cost Center", "Project", "Owner", "Name"]

violation[{}] if {
	instance_tags := [lower(key) | input.instance.tags[key]]
	missing_tags := {tag | tag := required_tags[_]; not lower(tag) in instance_tags}
    count(missing_tags) > 0
}

title := "Azure Virtual Machines should have required tags"
description := "Ensure that Azure Virtual Machines have all required tags to maintain consistency and compliance across resources" 