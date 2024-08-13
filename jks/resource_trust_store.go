package jks

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pavel-v-chernykh/keystore-go/v4"
	"time"
)

func resourceTrustStore() *schema.Resource {
	return &schema.Resource{
		Description:   "JKS trust store generated from one or more PEM encoded certificates.",
		CreateContext: resourceTrustStoreCreate,
		ReadContext:   resourceTrustStoreRead,
		DeleteContext: resourceTrustStoreDelete,
		Schema: map[string]*schema.Schema{
			"certificates": {
				Description: "CA certificates or chains to include in generated trust store; in PEM format.",
				Type:        schema.TypeList,
				Required:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				MinItems: 1,
				ForceNew: true,
			},
			"password": {
				Description: "Password to secure trust store. Defaults to empty string.",
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "",
				ForceNew:    true,
			},
			"jks": {
				Description: "JKS trust store data; base64 encoded.",
				Type:        schema.TypeString,
				Computed:    true,
			},
		},
	}
}

func resourceTrustStoreCreate(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	ks := keystore.New()

	chainCertsInterfaces := d.Get("certificates").([]interface{})
	if len(chainCertsInterfaces) == 0 {
		return diag.Errorf("empty certificates")
	}
	chainCerts := []string{}
	for _, ci := range chainCertsInterfaces {
		chainCerts = append(chainCerts, ci.(string))
	}

	keystoreCerts, err := transformPemCertsToKeystoreCert(chainCerts)
	if err != nil {
		return diag.Errorf("cant transform pem chainCerts to keystore chainCerts: %s", err.Error())
	}
	for i, keystoreCert := range keystoreCerts {
		err := ks.SetTrustedCertificateEntry(
			fmt.Sprintf("%d", i),
			keystore.TrustedCertificateEntry{
				CreationTime: time.Now(),
				Certificate:  keystoreCert,
			},
		)
		if err != nil {
			return diag.Errorf("cant add cert %d to truststore: %s", err.Error())
		}
	}

	var jksBuffer bytes.Buffer
	jksWriter := bufio.NewWriter(&jksBuffer)

	password := d.Get("password").(string)
	err = ks.Store(jksWriter, []byte(password))
	if err != nil {
		return diag.Errorf("failed to generate JKS: %s", err.Error())
	}

	err = jksWriter.Flush()
	if err != nil {
		return diag.Errorf("failed to flush JKS: %v", err)
	}

	jksData := base64.StdEncoding.EncodeToString(jksBuffer.Bytes())

	d.SetId(resourceTrustStoreGetId(d))

	if err = d.Set("jks", jksData); err != nil {
		return diag.Errorf("failed to save JKS: %v", err)
	}

	return nil
}

func resourceTrustStoreRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	if d.Id() == resourceTrustStoreGetId(d) {
		return nil
	}
	return resourceTrustStoreCreate(ctx, d, m)
}

func resourceTrustStoreGetId(d *schema.ResourceData) string {
	idHash := crypto.SHA1.New()
	idHash.Write([]byte(d.Get("password").(string)))
	for _, ci := range d.Get("certificates").([]interface{}) {
		idHash.Write([]byte(ci.(string)))
	}
	id := hex.EncodeToString(idHash.Sum([]byte{}))
	return id
}

func resourceTrustStoreDelete(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	d.SetId("")

	return diags
}
