package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"wanctl/internal/agent"
	"wanctl/internal/policy"
	"wanctl/internal/relay"
	"wanctl/internal/transport"

	"net/http/httptest"
)

// cliRun is one invocation of the real binary with a fixed config dir, which is
// what lets a test walk the two-process flow a person (or an AI) actually has:
// the refusal in one process, the pin in the next.
type cliRun struct {
	bin string
	dir string
	env []string
}

func (r cliRun) run(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(r.bin, args...)
	cmd.Env = append(os.Environ(), r.env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err == nil {
		return out.String(), 0
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("%v: %v\n%s", args, err, out.String())
	}
	return out.String(), exit.ExitCode()
}

// The device prints its answer itself: `wanctl verify <number>` derives the code
// from this installation's certificate, which is exactly what the controller
// derives from the certificate the dial was shown. This is the value a human
// compares, and it must not depend on the relay, the agent or the network.
func TestVerifyPrintsTheCodeAControllerDerivesFromTheSameCertificate(t *testing.T) {
	bin := buildWanctl(t)
	dir := t.TempDir()
	run := cliRun{bin: bin, dir: dir, env: []string{"WANCTL_CONFIG_DIR=" + dir, "WANCTL_RELAY=", "WANCTL_TOKEN="}}

	idOut, code := run.run(t, "id")
	if code != 0 {
		t.Fatalf("id exited %d:\n%s", code, idOut)
	}
	m := regexp.MustCompile(`fingerprint: (\S+)`).FindStringSubmatch(idOut)
	if m == nil {
		t.Fatalf("no fingerprint in:\n%s", idOut)
	}
	want, err := transport.VerifyCode(m[1], "482913")
	if err != nil {
		t.Fatal(err)
	}

	out, code := run.run(t, "verify", "482913")
	if code != 0 {
		t.Fatalf("verify exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "verification code: "+transport.GroupDigits(want)) {
		t.Fatalf("verify printed no %s:\n%s", transport.GroupDigits(want), out)
	}
	// The number arrives from a screen, with or without its grouping.
	grouped, code := run.run(t, "verify", "482 913")
	if code != 0 || !strings.Contains(grouped, transport.GroupDigits(want)) {
		t.Fatalf("grouped number exited %d and printed:\n%s", code, grouped)
	}
	// A different number is a different code: nothing here is a fixed value.
	other, err := transport.VerifyCode(m[1], "482914")
	if err != nil {
		t.Fatal(err)
	}
	if other == want {
		t.Fatal("two numbers derived one code")
	}
}

// Asking this installation to verify something must not be the moment it
// invents an identity: a machine that has never run wanctl has no fingerprint
// to answer with, and a freshly minted key pair answering instead would be a
// lie told with a straight face.
func TestVerifyRefusesToMintAnIdentityItWasOnlyAskedAbout(t *testing.T) {
	bin := buildWanctl(t)
	dir := t.TempDir()
	run := cliRun{bin: bin, dir: dir, env: []string{"WANCTL_CONFIG_DIR=" + dir, "WANCTL_RELAY=", "WANCTL_TOKEN="}}

	out, code := run.run(t, "verify", "482913")
	if code == 0 {
		t.Fatalf("verify on an installation with no identity succeeded:\n%s", out)
	}
	if !strings.Contains(out, "no wanctl identity") {
		t.Fatalf("refusal does not name the problem:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "cert.pem")); err == nil {
		t.Fatal("verify created an identity as a side effect")
	}
}

// The whole first-contact journey, through the real binary, against a real
// relay and a real agent: refuse with nine digits, pin with the code the DEVICE
// prints, then drive it. The middle step is the one this change exists for —
// nothing a human reads has to leave their two screens.
func TestFirstContactIsCheckedByTheCodeTheDevicePrints(t *testing.T) {
	bin := buildWanctl(t)
	srv := httptest.NewServer(relay.New(relay.EnvTokenStore("verify-cli:alice")).Handler())
	defer srv.Close()

	deviceDir := t.TempDir()
	t.Setenv("WANCTL_CONFIG_DIR", deviceDir)
	ag, err := agent.New(agent.Options{RelayURL: srv.URL, Token: "verify-cli", Name: "home-pc", AutoYes: true, Mode: policy.ModeBypass, Transport: "http"})
	if err != nil {
		t.Fatal(err)
	}
	defer ag.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	go ag.Run(ctx)
	time.Sleep(300 * time.Millisecond)

	controlDir := t.TempDir()
	run := cliRun{bin: bin, dir: controlDir, env: []string{
		"WANCTL_CONFIG_DIR=" + controlDir,
		"WANCTL_RELAY=" + srv.URL,
		"WANCTL_TOKEN=verify-cli",
		"WANCTL_TRANSPORT=http",
	}}

	// First contact, with nothing pinned: the refusal has to carry a number, a
	// code, and the command that uses them.
	first, code := run.run(t, "exec", "--target", "home-pc", "echo", "hi")
	if code == 0 {
		t.Fatalf("first contact ran the command instead of refusing:\n%s", first)
	}
	number := transportDigits(t, first, `verification number:\s+([0-9 ]+)`)
	code9 := transportDigits(t, first, `verification code:\s+([0-9 ]+)`)
	if !strings.Contains(first, "wanctl verify "+number) {
		t.Fatalf("refusal does not hand over the device-side command:\n%s", first)
	}

	// What the device itself prints for that number, run through the same
	// binary against the device's own config dir.
	onDevice, devCode := cliRun{bin: bin, dir: deviceDir, env: []string{"WANCTL_CONFIG_DIR=" + deviceDir, "WANCTL_RELAY=", "WANCTL_TOKEN="}}.run(t, "verify", number)
	if devCode != 0 {
		t.Fatalf("device-side verify exited %d:\n%s", devCode, onDevice)
	}
	if got := transportDigits(t, onDevice, `verification code:\s+([0-9 ]+)`); got != code9 {
		t.Fatalf("the refusal printed %s, the device printed %s", code9, got)
	}

	// A code the device never printed pins nothing.
	wrong := "000000000"
	if code9 == wrong {
		wrong = "111111111"
	}
	out, exit := run.run(t, "trust", "server", "--target", "home-pc", "--number", number, "--code", wrong)
	if exit == 0 {
		t.Fatalf("a fabricated code was accepted:\n%s", out)
	}
	if !strings.Contains(out, "VERIFICATION CODE MISMATCH") {
		t.Fatalf("wrong-code refusal is not matchable:\n%s", out)
	}
	if listed, _ := run.run(t, "trust", "servers"); !strings.Contains(listed, "pinned devices: 0") {
		t.Fatalf("a refused verification still pinned something:\n%s", listed)
	}

	// The code read off the device pins it, and the command runs.
	out, exit = run.run(t, "trust", "server", "--target", "home-pc", "--number", number, "--code", code9)
	if exit != 0 {
		t.Fatalf("pinning with the device's code exited %d:\n%s", exit, out)
	}
	if !strings.Contains(out, "pinned device") {
		t.Fatalf("pin did not report success:\n%s", out)
	}
	out, exit = run.run(t, "exec", "--target", "home-pc", "echo", "hi")
	if exit != 0 {
		t.Fatalf("exec after the pin exited %d:\n%s", exit, out)
	}
	if !strings.Contains(out, "hi") {
		t.Fatalf("exec printed no command output:\n%s", out)
	}
}

// transportDigits pulls a grouped number or code out of a message and returns
// it the way the commands take it: digits only.
func transportDigits(t *testing.T, text, pattern string) string {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(text)
	if m == nil {
		t.Fatalf("no match for %s in:\n%s", pattern, text)
	}
	digits := strings.ReplaceAll(strings.TrimSpace(m[1]), " ", "")
	if _, err := transport.NormalizeVerifyNumber(digits); err == nil {
		return digits
	}
	if _, err := transport.NormalizeVerifyCode(digits); err != nil {
		t.Fatalf("%q is neither a number nor a code", m[1])
	}
	return digits
}

// Fail closed, in the two ways a non-interactive caller can get it wrong: no
// flags at all (there is nothing to ask a terminal that is not there), and a
// number without a code. Neither may reach the trust store, because a pin is a
// record that a human checked something.
func TestTrustServerWithoutAVerificationPinsNothing(t *testing.T) {
	bin := buildWanctl(t)
	dir := t.TempDir()
	// A token and a relay are what client.New() needs before any strategy is
	// chosen; neither branch below dials, so the address never has to resolve.
	run := cliRun{bin: bin, dir: dir, env: []string{
		"WANCTL_CONFIG_DIR=" + dir,
		"WANCTL_RELAY=http://relay.invalid",
		"WANCTL_TOKEN=tok",
	}}

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no flags, no terminal", []string{"trust", "server", "--target", "home-pc"}, "needs a terminal"},
		{"number without the code", []string{"trust", "server", "--target", "home-pc", "--number", "482913"}, "--code is required"},
		{"code without a number", []string{"trust", "server", "--target", "home-pc", "--code", "771204638"}, "needs that --number"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, code := run.run(t, tc.args...)
			if code == 0 {
				t.Fatalf("%v succeeded:\n%s", tc.args, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("refusal does not say %q:\n%s", tc.want, out)
			}
			if listed, _ := run.run(t, "trust", "servers"); !strings.Contains(listed, "pinned devices: 0") {
				t.Fatalf("a refused confirmation pinned something:\n%s", listed)
			}
		})
	}
}
