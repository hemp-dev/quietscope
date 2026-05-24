package safety

import (
	"strings"
	"testing"
)

func TestSensitiveEnvNamesAreMasked(t *testing.T) {
	if !IsSensitiveEnvName("OPENAI_API_KEY") {
		t.Fatal("expected OPENAI_API_KEY to be sensitive")
	}
	if MaskSensitiveValue("OPENAI_API_KEY", "sk-real") != "***MASKED***" {
		t.Fatal("expected sensitive value to be masked")
	}
}

func TestRedactSensitiveText(t *testing.T) {
	input := "token=abc123 password: hunter2 Authorization: Bearer abcdefghijklmnop"
	got := RedactSensitiveText(input)
	if strings.Contains(got, "abc123") || strings.Contains(got, "hunter2") || strings.Contains(got, "abcdefghijklmnop") {
		t.Fatalf("secret-like value leaked: %s", got)
	}
}

func TestMaskPath(t *testing.T) {
	got := MaskPath("/Users/alice/project/.env", "/Users/alice", "alice")
	if got != "~/project/.env" {
		t.Fatalf("unexpected masked path: %s", got)
	}
}

func TestSafeJSONStringEscapesHTML(t *testing.T) {
	got := SafeJSONString("</script><img src=x>")
	if strings.Contains(got, "</script>") {
		t.Fatalf("unsafe JSON string: %s", got)
	}
}

func TestEscapeHTML(t *testing.T) {
	got := EscapeHTML(`<img src=x onerror=alert(1)>`)
	if strings.Contains(got, "<img") || !strings.Contains(got, "&lt;img") {
		t.Fatalf("expected HTML escaping, got %s", got)
	}
}
