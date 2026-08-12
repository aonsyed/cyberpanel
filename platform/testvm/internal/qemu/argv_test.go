package qemu

import (
	"reflect"
	"strings"
	"testing"
)

func TestBuildARM64HVFReturnsLiteralQEMU1103Invocation(t *testing.T) {
	t.Parallel()

	cfg := arm64Config()
	want := Invocation{
		Path: "/opt/homebrew/Cellar/qemu/11.0.3/bin/qemu-system-aarch64",
		Args: []string{
			"-no-user-config",
			"-nodefaults",
			"-name", "cp-arm64-test",
			"-machine", "virt-11.0",
			"-accel", "hvf",
			"-cpu", "host",
			"-m", "2048",
			"-smp", "2",
			"-display", "none",
			"-monitor", "none",
			"-no-reboot",
			"-boot", "order=c,strict=on",
			"-rtc", "base=utc",
			"-object", "rng-random,id=rng0,filename=/dev/urandom",
			"-device", "virtio-rng-pci,rng=rng0",
			"-drive", "if=pflash,format=raw,unit=0,readonly=on,file=/vm/arm64/edk2-code.fd",
			"-drive", "if=pflash,format=raw,unit=1,file=/vm/arm64/edk2-vars.fd",
			"-drive", "if=none,id=osdisk,format=qcow2,cache=none,aio=threads,file=/vm/arm64/overlay.qcow2",
			"-device", "virtio-blk-pci,drive=osdisk",
			"-drive", "if=none,id=seed,format=raw,readonly=on,file=/vm/arm64/cidata.iso",
			"-device", "virtio-blk-pci,drive=seed",
			"-netdev", "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:0-:22",
			"-device", "virtio-net-pci,netdev=net0",
			"-qmp", "unix:/vm/arm64/qmp.sock,server=on,wait=off",
			"-serial", "file:/vm/arm64/serial.log",
		},
		NonPerformanceEvidence: false,
	}

	got, err := Build(cfg)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Build() mismatch\n got: %#v\nwant: %#v", got, want)
	}
	if err := Validate(cfg, got); err != nil {
		t.Fatalf("Validate(Build()) error = %v", err)
	}
}

func TestBuildAMD64TCGReturnsLiteralQEMU1103Invocation(t *testing.T) {
	t.Parallel()

	cfg := amd64Config()
	want := Invocation{
		Path: "/opt/homebrew/Cellar/qemu/11.0.3/bin/qemu-system-x86_64",
		Args: []string{
			"-no-user-config",
			"-nodefaults",
			"-name", "cp-amd64-test",
			"-machine", "pc-q35-11.0",
			"-accel", "tcg,thread=multi",
			"-cpu", "max",
			"-m", "2048",
			"-smp", "2",
			"-display", "none",
			"-monitor", "none",
			"-no-reboot",
			"-boot", "order=c,strict=on",
			"-rtc", "base=utc",
			"-object", "rng-random,id=rng0,filename=/dev/urandom",
			"-device", "virtio-rng-pci,rng=rng0",
			"-drive", "if=pflash,format=raw,unit=0,readonly=on,file=/vm/amd64/edk2-code.fd",
			"-drive", "if=pflash,format=raw,unit=1,file=/vm/amd64/edk2-vars.fd",
			"-drive", "if=none,id=osdisk,format=qcow2,cache=none,aio=threads,file=/vm/amd64/overlay.qcow2",
			"-device", "virtio-blk-pci,drive=osdisk",
			"-drive", "if=none,id=seed,format=raw,readonly=on,file=/vm/amd64/cidata.iso",
			"-device", "virtio-blk-pci,drive=seed",
			"-netdev", "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:22022-:22",
			"-device", "virtio-net-pci,netdev=net0",
			"-qmp", "unix:/vm/amd64/qmp.sock,server=on,wait=off",
			"-serial", "file:/vm/amd64/serial.log",
		},
		NonPerformanceEvidence: true,
	}

	got, err := Build(cfg)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Build() mismatch\n got: %#v\nwant: %#v", got, want)
	}
	if err := Validate(cfg, got); err != nil {
		t.Fatalf("Validate(Build()) error = %v", err)
	}
}

func TestBuildRejectsOpenEndedOrUnsupportedConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "wrong QEMU version",
			mutate: func(cfg *Config) {
				cfg.QEMUVersion = "11.0.2"
			},
			wantErr: "qemu version",
		},
		{
			name: "unknown profile",
			mutate: func(cfg *Config) {
				cfg.Profile = Profile("arm64-tcg-fallback")
			},
			wantErr: "profile",
		},
		{
			name: "wrong ARM executable",
			mutate: func(cfg *Config) {
				cfg.QEMUPath = "/opt/homebrew/bin/qemu-system-x86_64"
			},
			wantErr: "qemu path",
		},
		{
			name: "empty VM name",
			mutate: func(cfg *Config) {
				cfg.Name = ""
			},
			wantErr: "name",
		},
		{
			name: "QEMU suboption injection through VM name",
			mutate: func(cfg *Config) {
				cfg.Name = "guest,process=hidden"
			},
			wantErr: "name",
		},
		{
			name: "overlong VM name",
			mutate: func(cfg *Config) {
				cfg.Name = strings.Repeat("n", 65)
			},
			wantErr: "name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := arm64Config()
			tt.mutate(&cfg)

			_, err := Build(cfg)
			if err == nil {
				t.Fatal("Build() error = nil, want rejection")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tt.wantErr) {
				t.Fatalf("Build() error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestBuildRejectsUnsafePathsBeforeTheyReachQEMU(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		field  string
		value  string
		mutate func(*Config, string)
	}{
		{"relative QEMU", "qemu path", "qemu-system-aarch64", func(c *Config, v string) { c.QEMUPath = v }},
		{"QEMU newline", "qemu path", "/opt/qemu-system-aarch64\n-daemonize", func(c *Config, v string) { c.QEMUPath = v }},
		{"relative pflash code", "pflash code path", "edk2-code.fd", func(c *Config, v string) { c.PFlashCodePath = v }},
		{"pflash vars comma", "pflash vars path", "/vm/vars.fd,readonly=on", func(c *Config, v string) { c.PFlashVarsPath = v }},
		{"disk carriage return", "disk path", "/vm/disk.qcow2\r-cache=unsafe", func(c *Config, v string) { c.DiskPath = v }},
		{"seed traversal", "seed path", "/vm/../secrets/cidata.iso", func(c *Config, v string) { c.SeedPath = v }},
		{"QMP tab", "qmp socket path", "/vm/qmp\t.sock", func(c *Config, v string) { c.QMPSocketPath = v }},
		{"serial NUL", "serial path", "/vm/serial\x00.log", func(c *Config, v string) { c.SerialPath = v }},
		{"invalid UTF-8 seed", "seed path", string([]byte{'/', 'v', 'm', '/', 0xff}), func(c *Config, v string) { c.SeedPath = v }},
		{"root serial", "serial path", "/", func(c *Config, v string) { c.SerialPath = v }},
		{"overlong QMP socket", "qmp socket path", "/vm/" + strings.Repeat("q", 100), func(c *Config, v string) { c.QMPSocketPath = v }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := arm64Config()
			tt.mutate(&cfg, tt.value)

			_, err := Build(cfg)
			if err == nil {
				t.Fatal("Build() error = nil, want unsafe path rejection")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tt.field) {
				t.Fatalf("Build() error = %q, want field %q", err, tt.field)
			}
		})
	}
}

func TestBuildRejectsTwoResourcesAtTheSamePath(t *testing.T) {
	t.Parallel()

	cfg := arm64Config()
	cfg.SeedPath = cfg.DiskPath

	_, err := Build(cfg)
	if err == nil {
		t.Fatal("Build() error = nil, want duplicate resource path rejection")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "must differ") {
		t.Fatalf("Build() error = %q, want duplicate path diagnostic", err)
	}
}

func TestValidateRejectsUnsafeInvocationMutations(t *testing.T) {
	t.Parallel()

	cfg := arm64Config()
	base, err := Build(cfg)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Invocation)
	}{
		{
			name: "shell executable",
			mutate: func(inv *Invocation) {
				inv.Path = "/bin/sh"
			},
		},
		{
			name: "missing no-user-config",
			mutate: func(inv *Invocation) {
				inv.Args = removeToken(inv.Args, "-no-user-config")
			},
		},
		{
			name: "missing nodefaults",
			mutate: func(inv *Invocation) {
				inv.Args = removeToken(inv.Args, "-nodefaults")
			},
		},
		{
			name: "display enabled",
			mutate: func(inv *Invocation) {
				replaceOptionValue(inv.Args, "-display", "cocoa")
			},
		},
		{
			name: "monitor enabled",
			mutate: func(inv *Invocation) {
				replaceOptionValue(inv.Args, "-monitor", "stdio")
			},
		},
		{
			name: "wrong machine",
			mutate: func(inv *Invocation) {
				replaceOptionValue(inv.Args, "-machine", "virt")
			},
		},
		{
			name: "wrong CPU",
			mutate: func(inv *Invocation) {
				replaceOptionValue(inv.Args, "-cpu", "max")
			},
		},
		{
			name: "duplicate accelerator",
			mutate: func(inv *Invocation) {
				inv.Args = append(inv.Args, "-accel", "hvf")
			},
		},
		{
			name: "fallback accelerator list",
			mutate: func(inv *Invocation) {
				replaceOptionValue(inv.Args, "-accel", "hvf:tcg")
			},
		},
		{
			name: "accelerator hidden in machine",
			mutate: func(inv *Invocation) {
				replaceOptionValue(inv.Args, "-machine", "virt-11.0,accel=hvf:tcg")
			},
		},
		{
			name: "non-loopback forwarding",
			mutate: func(inv *Invocation) {
				replaceOptionValue(inv.Args, "-netdev", "user,id=net0,restrict=on,hostfwd=tcp:0.0.0.0:0-:22")
			},
		},
		{
			name: "network restriction disabled",
			mutate: func(inv *Invocation) {
				replaceOptionValue(inv.Args, "-netdev", "user,id=net0,restrict=off,hostfwd=tcp:127.0.0.1:0-:22")
			},
		},
		{
			name: "writable 9p share",
			mutate: func(inv *Invocation) {
				inv.Args = append(inv.Args, "-virtfs", "local,path=/Users,security_model=none,mount_tag=host")
			},
		},
		{
			name: "writable fsdev share",
			mutate: func(inv *Invocation) {
				inv.Args = append(inv.Args, "-fsdev", "local,id=host,path=/Users,security_model=none")
			},
		},
		{
			name: "writable FAT share",
			mutate: func(inv *Invocation) {
				inv.Args = append(inv.Args, "-drive", "file=fat:rw:/Users")
			},
		},
		{
			name: "daemonized process",
			mutate: func(inv *Invocation) {
				inv.Args = append(inv.Args, "-daemonize")
			},
		},
		{
			name: "double-dash daemonized process",
			mutate: func(inv *Invocation) {
				inv.Args = append(inv.Args, "--daemonize")
			},
		},
		{
			name: "substituted pflash code",
			mutate: func(inv *Invocation) {
				replaceExact(inv.Args,
					"if=pflash,format=raw,unit=0,readonly=on,file=/vm/arm64/edk2-code.fd",
					"if=pflash,format=raw,unit=0,readonly=on,file=/tmp/other-code.fd")
			},
		},
		{
			name: "substituted pflash vars",
			mutate: func(inv *Invocation) {
				replaceExact(inv.Args,
					"if=pflash,format=raw,unit=1,file=/vm/arm64/edk2-vars.fd",
					"if=pflash,format=raw,unit=1,file=/tmp/shared-vars.fd")
			},
		},
		{
			name: "substituted disk",
			mutate: func(inv *Invocation) {
				replaceExact(inv.Args,
					"if=none,id=osdisk,format=qcow2,cache=none,aio=threads,file=/vm/arm64/overlay.qcow2",
					"if=none,id=osdisk,format=qcow2,cache=unsafe,file=/tmp/other.qcow2")
			},
		},
		{
			name: "substituted seed",
			mutate: func(inv *Invocation) {
				replaceExact(inv.Args,
					"if=none,id=seed,format=raw,readonly=on,file=/vm/arm64/cidata.iso",
					"if=none,id=seed,format=raw,readonly=on,file=/tmp/other.iso")
			},
		},
		{
			name: "TCP QMP",
			mutate: func(inv *Invocation) {
				replaceOptionValue(inv.Args, "-qmp", "tcp:0.0.0.0:4444,server=on,wait=off")
			},
		},
		{
			name: "substituted serial sink",
			mutate: func(inv *Invocation) {
				replaceOptionValue(inv.Args, "-serial", "file:/tmp/serial.log")
			},
		},
		{
			name: "false evidence classification",
			mutate: func(inv *Invocation) {
				inv.NonPerformanceEvidence = true
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mutated := cloneInvocation(base)
			tt.mutate(&mutated)
			if err := Validate(cfg, mutated); err == nil {
				t.Fatal("Validate() error = nil, want unsafe mutation rejection")
			}
		})
	}
}

func TestValidateRequiresTCGToRemainNonPerformanceEvidence(t *testing.T) {
	t.Parallel()

	cfg := amd64Config()
	inv, err := Build(cfg)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	inv.NonPerformanceEvidence = false

	if err := Validate(cfg, inv); err == nil {
		t.Fatal("Validate() error = nil, want TCG evidence classification rejection")
	}
}

func arm64Config() Config {
	return Config{
		Profile:        ProfileARM64HVF,
		QEMUVersion:    SupportedQEMUVersion,
		QEMUPath:       "/opt/homebrew/Cellar/qemu/11.0.3/bin/qemu-system-aarch64",
		Name:           "cp-arm64-test",
		PFlashCodePath: "/vm/arm64/edk2-code.fd",
		PFlashVarsPath: "/vm/arm64/edk2-vars.fd",
		DiskPath:       "/vm/arm64/overlay.qcow2",
		SeedPath:       "/vm/arm64/cidata.iso",
		QMPSocketPath:  "/vm/arm64/qmp.sock",
		SerialPath:     "/vm/arm64/serial.log",
		SSHHostPort:    0,
	}
}

func amd64Config() Config {
	return Config{
		Profile:        ProfileAMD64TCG,
		QEMUVersion:    SupportedQEMUVersion,
		QEMUPath:       "/opt/homebrew/Cellar/qemu/11.0.3/bin/qemu-system-x86_64",
		Name:           "cp-amd64-test",
		PFlashCodePath: "/vm/amd64/edk2-code.fd",
		PFlashVarsPath: "/vm/amd64/edk2-vars.fd",
		DiskPath:       "/vm/amd64/overlay.qcow2",
		SeedPath:       "/vm/amd64/cidata.iso",
		QMPSocketPath:  "/vm/amd64/qmp.sock",
		SerialPath:     "/vm/amd64/serial.log",
		SSHHostPort:    22022,
	}
}

func cloneInvocation(in Invocation) Invocation {
	out := in
	out.Args = append([]string(nil), in.Args...)
	return out
}

func removeToken(args []string, token string) []string {
	result := make([]string, 0, len(args))
	for _, arg := range args {
		if arg != token {
			result = append(result, arg)
		}
	}
	return result
}

func replaceOptionValue(args []string, option, replacement string) {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == option {
			args[i+1] = replacement
			return
		}
	}
}

func replaceExact(args []string, old, replacement string) {
	for i := range args {
		if args[i] == old {
			args[i] = replacement
			return
		}
	}
}
