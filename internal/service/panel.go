package service

import (
	_ "embed"
	"os"
	"os/exec"
)

//go:embed panel.py
var panelProgram string

func RunPanel(args ...string) error {
	cmd := exec.Command("/usr/bin/python3", append([]string{"-I", "-c", panelProgram}, args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C.UTF-8", "HOME=/root"}
	cmd.Dir = "/"
	return cmd.Run()
}

func revokePanel() error {
	if _, err := os.Stat("/var/lib/rkn-guard-panel"); os.IsNotExist(err) {
		return nil
	}
	return RunPanel("revoke")
}
