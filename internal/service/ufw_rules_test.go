package service

import (
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestUFWBlockPriorityAndMigration(t *testing.T) {
	for _, chain := range []string{"ufw-before-input", "ufw6-before-input"} {
		block := "# SCANNERS-BLOCK chain - managed by antiscan\n:SCANNERS-BLOCK - [0:0]\n-A " + chain + " -j SCANNERS-BLOCK\n-A SCANNERS-BLOCK -j RETURN\n# END SCANNERS-BLOCK\n"
		original := "*filter\n:" + chain + " - [0:0]\n-A " + chain + " -j ACCEPT\nCOMMIT\n*nat\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n"
		legacy := strings.Replace(original, "COMMIT", block+"COMMIT", 1)
		svc := &IptablesService{logger: zerolog.Nop()}
		clean := svc.removeManagedBlock(legacy, "# SCANNERS-BLOCK chain - managed by antiscan")
		result, err := insertUFWBlock(clean, block, chain)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Index(result, "-j SCANNERS-BLOCK") > strings.Index(result, "-j ACCEPT") {
			t.Fatal("jump follows ACCEPT")
		}
		if !strings.HasSuffix(result, "*nat\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n") {
			t.Fatal("changed unrelated table")
		}
		if svc.removeManagedBlock(result, "# SCANNERS-BLOCK chain - managed by antiscan") != original {
			t.Fatal("changed unrelated rules")
		}
		second, err := insertUFWBlock(svc.removeManagedBlock(result, "# SCANNERS-BLOCK chain - managed by antiscan"), block, chain)
		if err != nil || second != result {
			t.Fatal("repeated setup changes rules or duplicates block")
		}
	}
}

func TestUFWBlockRejectsMalformedTables(t *testing.T) {
	for _, content := range []string{
		"*nat\nCOMMIT\n", "*filter\nCOMMIT\n", "*filter\n:ufw-before-input - [0:0]\n",
		"*filter\n:ufw-before-input - [0:0]\nCOMMIT\n*filter\nCOMMIT\n",
		"*filter\n:ufw-before-input - [0:0]\n-A ufw-before-input -j ACCEPT\n:LATE - [0:0]\nCOMMIT\n",
	} {
		if _, err := insertUFWBlock(content, "block", "ufw-before-input"); err == nil {
			t.Fatalf("accepted malformed file: %q", content)
		}
	}
}
