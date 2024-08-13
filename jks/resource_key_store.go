package jks

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pavel-v-chernykh/keystore-go/v4"
	"strings"
	"time"
)

func resourceKeyStore() *schema.Resource {
	return &schema.Resource{
		Description:   "JKS trust store generated from private key and certificate.",
		CreateContext: resourceKeyStoreCreate,
		ReadContext:   resourceKeyStoreRead,
		DeleteContext: resourceKeyStoreDelete,
		Schema: map[string]*schema.Schema{
			"private_key": {
				Description: "Private key to include in generated key store; in PEM format.",
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
			},
			"certificate_chain": {
				Description: "Certificates key to include in generated key store; in PEM format.",
				Type:        schema.TypeList,
				Required:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				MinItems: 1,
				ForceNew: true,
			},
			"ca": {
				Description: "Certificates key to include in generated key store; in PEM format.",
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
			},
			"password": {
				Description: "Password to secure key store. Defaults to empty string.",
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
			},
			"jks": {
				Description: "JKS key store data; base64 encoded.",
				Type:        schema.TypeString,
				Computed:    true,
			},
		},
	}
}

func resourceKeyStoreCreate(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	ks := keystore.New()

	privateKeyDecoded, err := DecodePrivateKeyBytes([]byte(strings.TrimSpace(d.Get("private_key").(string))))
	if err != nil {
		return diag.Errorf("cant decode private key: %s", err.Error())
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(privateKeyDecoded)
	if err != nil {
		return diag.Errorf("cant marshal private key to pkcs8: %s", err.Error())
	}

	chainCertsInterfaces := d.Get("certificate_chain").([]interface{})
	chainCerts := []string{}
	for _, ci := range chainCertsInterfaces {
		chainCerts = append(chainCerts, ci.(string))
	}
	keystoreCerts, err := transformPemCertsToKeystoreCert(chainCerts)
	if err != nil {
		return diag.Errorf("cant transform pem certs to keystore certs %v", err.Error())
	}

	err = ks.SetPrivateKeyEntry(
		"certificate",
		keystore.PrivateKeyEntry{
			CreationTime:     time.Now(),
			PrivateKey:       privateKey,
			CertificateChain: keystoreCerts,
		},
		[]byte(d.Get("password").(string)),
	)
	if err != nil {
		return diag.Errorf("cant set private key entry %s", err.Error())
	}

	caPem := strings.TrimSpace(d.Get("ca").(string))
	if len(caPem) > 0 {
		caCerts, err := transformPemCertsToKeystoreCert([]string{caPem})
		if err != nil {
			return diag.Errorf("cant ca pem to keystore format: %s", err.Error())
		}
		err = ks.SetTrustedCertificateEntry(
			"ca",
			keystore.TrustedCertificateEntry{
				CreationTime: time.Now(),
				Certificate:  caCerts[0],
			},
		)
		if err != nil {
			return diag.Errorf("cant set ca entry %s", err.Error())
		}
	}

	jksBuffer := bytes.NewBuffer(nil)
	jksWriter := bufio.NewWriter(jksBuffer)

	err = ks.Store(jksWriter, []byte(d.Get("password").(string)))
	if err != nil {
		return diag.Errorf("Failed to generate JKS: %v", err)
	}

	err = jksWriter.Flush()
	if err != nil {
		return diag.Errorf("Failed to flush JKS: %v", err)
	}

	jksData := base64.StdEncoding.EncodeToString(jksBuffer.Bytes())

	d.SetId(resourceKeyStoreGetId(d))

	if err = d.Set("jks", jksData); err != nil {
		return diag.Errorf("Failed to save JKS: %v", err)
	}

	return nil
}

func resourceKeyStoreGetId(d *schema.ResourceData) string {
	idHash := crypto.SHA1.New()
	idHash.Write([]byte(d.Get("private_key").(string)))
	idHash.Write([]byte(d.Get("ca").(string)))
	idHash.Write([]byte(d.Get("password").(string)))
	for _, ci := range d.Get("certificate_chain").([]interface{}) {
		idHash.Write([]byte(ci.(string)))
	}
	id := hex.EncodeToString(idHash.Sum([]byte{}))
	return id
}

func resourceKeyStoreRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	if d.Id() == resourceKeyStoreGetId(d) {
		return nil
	}
	return resourceKeyStoreCreate(ctx, d, m)
}

func resourceKeyStoreDelete(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	d.SetId("")
	return nil
}
