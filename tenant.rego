package tenant.update

persmission := {"tenant:write", "tenant:admin"}

claim := "https:api.dev.atym.io/tenant"

default allow := false

allow if {
	claim in input.claims
	input.tenant == input.uri_tenant

	# convert input array to rego set for intersection check
	user_permissions := {role | role := input.permissions[_]}
	count(persmission & user_permissions) > 0
}
