package compliance_framework.template.azure_virtual_machines._deny_missing_tags

required_tags := ["Environment", "Security", "Compliance", "Application", "Cost Center", "Project", "Owner", "Name"]

violation[{
    "title": "Check to ensure correct tags are set on Azure VM Instances",
    "description": sprintf("Instance '%v' is missing required tags: %v", [input.Name, missing_tags]),
    "remarks": "Ensure the following tags are set on the Azure VM instance: Environment, Owner, compliance, confidentiality, backup, role."
}] if {
    tags := {lower(tag.Key): lower(tag.Value) | tag := input.Tags[_]}
    missing_tags := {tag | tag := required_tags[_]; not tag_exists(tags, tag)}
    count(missing_tags) > 0
}

tag_exists(tags, tag_name) if {
    tags[lower(tag_name)]
}
