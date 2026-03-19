package github

import (
	"strings"
)

type Permissions map[string]string

func (p Permissions) ContainsOrganizationPermission() bool {
	for name := range p {
		if isOrganizationPermission(name) {
			return true
		}
	}

	return false
}

// Organization permissions that are not prefixed with "organization_".
var organizationPermissions = map[string]bool{
	"administration":                                 true,
	"custom_properties_for_organizations":            true,
	"enterprise_custom_properties_for_organizations": true,
	"members": true,
	"plan":    true,
}

func isOrganizationPermission(name string) bool {
	return strings.HasPrefix(name, "organization_") || organizationPermissions[name]
}
