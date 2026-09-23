//go:build !linux

package service

import (
	"fmt"
	"os"
)

// Тесты можно запускать на любой ОС, но работу с firewall разрешаем только в Linux.
func AcquireLock() (*os.File, error) {
	return nil, fmt.Errorf("firewall operations require Linux")
}
