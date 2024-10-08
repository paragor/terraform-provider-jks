package jks

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Provider -
func Provider() *schema.Provider {
	return &schema.Provider{
		ResourcesMap: map[string]*schema.Resource{
			"jks_trust_store": resourceTrustStore(),
			"jks_key_store":   resourceKeyStore(),
		},
		DataSourcesMap: map[string]*schema.Resource{},
	}
}
