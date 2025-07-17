package compliance_framework.ingress_allowed_all

title := "Azure Virtual Machines should not have ingress allowed from all sources"
description := "Ensure that Azure Virtual Machines do not have ingress allowed from all sources. While default security groups may allow ingress from all sources, custom security groups should not. A violation is triggered if any custom security group has an inbound rule that allows traffic from all sources."

# ——————————————————————————————
# Gather all the security-groups attached to every interface
# ——————————————————————————————
security_groups := [ni.security_group |
	some ni in input.network_interfaces

	# only include if it actually has one
	ni.security_group
]

# ——————————————————————————————
# Normalize & collect every rule (default + custom) in every SG
# ——————————————————————————————
all_rules := [normalise_rule(r) |
	some sg in security_groups

	# concat defaultSecurityRules + securityRules
	some r in array.concat(sg.properties.securityRules, sg.properties.defaultSecurityRules)
	r.properties.provisioningState == "Succeeded"
]

# ——————————————————————————————
# “Open” inbound rules: direction=inbound, srcPrefixes contains "*"
# ——————————————————————————————
open_rules contains rule if {
	some rule in all_rules
	rule.direction == "inbound"

	# does one of its srcPrefixes == "*"
	some i
	rule.srcPrefixes[i] == "*"
}

# ——————————————————————————————
# Deny if the highest-priority ‘open’ rule actually allows
# ——————————————————————————————
violation[{}] if {
	# build a map priority → rule
	pr_map := {rw.priority: rw | rw := open_rules[_]}

	# find the lowest numeric priority value among open_rules
	min_pr := min([rw.priority | some rw in open_rules])

	# pick that rule
	winner := pr_map[min_pr]

	# if it says “allow”, we fire deny
	winner.action == "allow"
}

# ——————————————————————————————
# helper: normalize one raw ARM NSG rule into a uniform shape
# ——————————————————————————————
normalise_rule(r) := {
	"direction": lower(r.properties.direction),
	"action": lower(r.properties.access),
	"priority": r.properties.priority,
	"dstPrefixes": normalise_list(r.properties.destinationAddressPrefix, r.properties.destinationAddressPrefixes),
	"dstPorts": [p | p := array.concat([r.properties.destinationPortRange], r.properties.destinationPortRanges)[_]; p != ""],
	"srcPrefixes": normalise_list(r.properties.sourceAddressPrefix, r.properties.sourceAddressPrefixes),
	"srcPorts": [p | p := array.concat([r.properties.sourcePortRange], r.properties.sourcePortRanges)[_]; p != ""],
}

# flatten singular+plural, drop empty, sort
normalise_list(single, list) := sorted if {
	combined := array.concat(list, [single])
	sorted := sort([x | some x in combined; x != ""])
}
