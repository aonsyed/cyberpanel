package apiserver

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestApplicationInstallClientIdentityInput(t *testing.T) {
	base := ApplicationInstallEdgePayload{SiteID: "site-test", DatabaseInstanceID: "database-test", Application: "wordpress", Version: "7.1.0", AdministratorUsername: "admin", AdministratorEmail: "admin@example.test", AdministratorDisplayName: "Administrator", AdministratorPassword: "fixture-password-long", DatabaseClientCertificate: "certificate-fixture", DatabaseClientKey: "private-key-fixture"}
	if err := validateApplicationInstall(&base); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*ApplicationInstallEdgePayload){
		func(p *ApplicationInstallEdgePayload) { p.DatabaseClientCertificate = "" },
		func(p *ApplicationInstallEdgePayload) { p.DatabaseClientKey = "" },
		func(p *ApplicationInstallEdgePayload) { p.DatabaseClientCertificate = strings.Repeat("x", 64<<10+1) },
		func(p *ApplicationInstallEdgePayload) { p.DatabaseClientKey = "key\x00fixture" },
		func(p *ApplicationInstallEdgePayload) { p.Application = "joomla" },
	} {
		p := base
		change(&p)
		if validateApplicationInstall(&p) == nil {
			t.Fatal("invalid client identity input accepted")
		}
	}
	payload := base
	material := takeApplicationInstallMaterial(&payload)
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{base.AdministratorPassword, base.DatabaseClientCertificate, base.DatabaseClientKey} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("private material retained in operation payload")
		}
	}
	encoded, err = json.Marshal(material)
	if err != nil || string(encoded) != "{}" {
		t.Fatal("private transport material serializes into JSON")
	}
	if string(material.DatabaseClientKey) != base.DatabaseClientKey || string(material.AdministratorPassword) != base.AdministratorPassword {
		t.Fatal("private input not transferred")
	}
	material.clear()
	for _, value := range [][]byte{material.AdministratorPassword, material.DatabaseClientCertificate, material.DatabaseClientKey} {
		for _, b := range value {
			if b != 0 {
				t.Fatal("private input not wiped")
			}
		}
	}
}

func TestHostingCloneClientIdentityInput(t *testing.T) {
	payload:=HostingClonePayload{PrimaryHostname:"clone.example.test",ProjectID:"project-test",DatabaseInstanceID:"external-test",CopyDatabase:true,AccessCredentialRef:"staging-credential",DatabaseClientCertificate:"target-certificate",DatabaseClientKey:"target-private-key"}
	if err:=validateHostingClone(&payload);err!=nil { t.Fatal(err) }
	partial:=payload;partial.DatabaseClientKey=""
	if validateHostingClone(&partial)==nil { t.Fatal("partial clone client identity accepted") }
	material:=takeApplicationCloneMaterial(&payload)
	if payload.DatabaseClientKey!="" || payload.DatabaseClientCertificate!="" || string(material.DatabaseClientKey)!="target-private-key" { t.Fatal("clone identity not separated from payload") }
	encoded,err:=json.Marshal(material);if err!=nil || string(encoded)!="{}" { t.Fatal("clone private material serialized") }
	material.clear()
	for _,b:=range material.DatabaseClientKey { if b!=0 { t.Fatal("clone key not wiped") } }
}
