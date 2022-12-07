package authz

import future.keywords.if
import future.keywords.in

# Default is to deny
default allow = false

allow if {
	has_global_rights
}

allow if {
	input.path[0] == "application"
	has_correct_role
}

allow if {
	input.path[0] == "application"
	is_creator
}

allow if {
	input.path[0] == "application"

	#application is in the correct status
	can_review

	# The file is not a draft
	not draft

	# The file is official
	official_file
}

is_creator if {
	input.userId == data.applications[input.path[1]].creator
}

can_review if {
	app := data.applications[input.path[1]]
	app.reviewers[input.userId]
	app.status in {500, 550, 600, 700, 800, 1200, 1250}
}

has_global_rights if {
	# Check roles
	some role in data.roles[input.userId].roles
	role.name == "admin"

	# tenantId == null means global role
	role.tenantId == null
}

has_correct_role if {
	# Check roles
	some role in data.roles[input.userId].roles
	role.name == "admin"

	# The role is tied to the correct tenant
	role.tenantId == input.tenantId

	# The action is set to allow
	data.tenants[input.tenantId].rules[role.name][input.action]
}

draft if {
	input.path[2] == "files"
	data.applications[input.path[1]].files[input.path[3]].draft
}

official_file if {
	input.path[2] == "files"
	data.applications[input.path[1]].files[input.path[3]].official
}

# Debug
debugRoles := data.roles[input.userId]

debugApplication := data.applications[input.path[1]]
