package apps

import "testing"

func TestDatabaseBindingPlacementBoundary(t *testing.T) {
	base := DatabaseBinding{
		ID: "appdb-test", InstanceID: "mariadb-local", Placement: "local",
		Engine: "mariadb", DatabaseName: "cp_test", PrincipalName: "cp_test",
		EndpointRef: "local-mariadb", PasswordRef: "app-secret", TLSRequired: true,
	}
	tests := []struct {
		name string
		change func(*DatabaseBinding)
		valid bool
	}{
		{"local", func(b *DatabaseBinding) {}, true},
		{"external", func(b *DatabaseBinding) { b.Placement = "external"; b.InstanceID = "remote-db"; b.EndpointRef = "db.example.com:3306" }, true},
		{"external IPv6", func(b *DatabaseBinding) { b.Placement = "external"; b.InstanceID = "remote-db"; b.EndpointRef = "[2001:db8::1]:3306" }, true},
		{"local with remote endpoint", func(b *DatabaseBinding) { b.EndpointRef = "db.example.com:3306" }, false},
		{"external with local sentinel", func(b *DatabaseBinding) { b.Placement = "external" }, false},
		{"external without TLS", func(b *DatabaseBinding) { b.Placement = "external"; b.EndpointRef = "db.example.com:3306"; b.TLSRequired = false }, false},
		{"unknown engine", func(b *DatabaseBinding) { b.Engine = "unknown" }, false},
		{"zero port", func(b *DatabaseBinding) { b.Placement = "external"; b.EndpointRef = "db.example.com:0" }, false},
		{"overflow port", func(b *DatabaseBinding) { b.Placement = "external"; b.EndpointRef = "db.example.com:65536" }, false},
		{"missing instance", func(b *DatabaseBinding) { b.InstanceID = "" }, false},
		{"missing password", func(b *DatabaseBinding) { b.PasswordRef = "" }, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binding := base
			test.change(&binding)
			err := binding.Validate()
			if (err == nil) != test.valid {
				t.Fatalf("Validate() = %v, want valid=%v", err, test.valid)
			}
		})
	}
}
