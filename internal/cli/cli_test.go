package cli

import (
	"bufio"
	"strings"
	"testing"
)

func TestL3MenuEOFAndCLIValidation(t *testing.T) {
	// 1. readTrimmed on EOF must return ok=false (preventing infinite 100% CPU menu loop)
	r := bufio.NewReader(strings.NewReader(""))
	if _, ok := readTrimmed(r); ok {
		t.Fatal("expected readTrimmed on EOF to return ok=false")
	}
	r2 := bufio.NewReader(strings.NewReader("12"))
	if got, ok := readTrimmed(r2); !ok || got != "12" {
		t.Fatalf("expected non-empty trailing line without newline to return (\"12\", true), got (%q, %v)", got, ok)
	}
	if _, ok := readTrimmed(r2); ok {
		t.Fatal("expected second readTrimmed after EOF to return ok=false")
	}

	// 2. RenameInstance validates oldName as well as newName
	if err := RenameInstance("../bad", "good"); err == nil {
		t.Fatal("expected RenameInstance to reject invalid oldName")
	}
	if err := RenameInstance("xoga", "good"); err == nil {
		t.Fatal("expected RenameInstance to reject renaming default instance xoga")
	}
	if err := RenameInstance("good", "../bad"); err == nil {
		t.Fatal("expected RenameInstance to reject invalid newName")
	}

	// 3. parseShowLogsArgs validates instance names, supports -n/--lines, and recognizes numeric instances
	if _, _, _, err := parseShowLogsArgs([]string{"../../etc"}, nil); err == nil {
		t.Fatal("expected parseShowLogsArgs to reject path traversal instance name")
	}
	inst, lines, follow, err := parseShowLogsArgs([]string{"101", "-n", "250", "-f"}, func(n string) bool {
		return n == "101"
	})
	if err != nil || inst != "101" || lines != "250" || !follow {
		t.Fatalf("numeric instance name misparsed: inst=%q lines=%q follow=%v err=%v", inst, lines, follow, err)
	}
	inst2, lines2, follow2, err := parseShowLogsArgs([]string{"500"}, func(n string) bool {
		return false
	})
	if err != nil || inst2 != "xoga" || lines2 != "500" || follow2 {
		t.Fatalf("numeric line count misparsed: inst=%q lines=%q follow=%v err=%v", inst2, lines2, follow2, err)
	}
}
