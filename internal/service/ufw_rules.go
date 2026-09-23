package service

import (
	"fmt"
	"strings"
)

// Вставляем блок в таблицу filter после объявлений цепочек, но перед правилами.
// Так каждый reload UFW восстанавливает тот же порядок переходов.
func insertUFWBlock(content, block, chain string) (string, error) {
	lines := strings.SplitAfter(content, "\n")
	inFilter, found, declared := false, false, false
	position, offset := -1, 0
	for _, line := range lines {
		text := strings.TrimSpace(line)
		if strings.HasPrefix(text, "*") {
			if inFilter {
				return "", fmt.Errorf("unterminated filter table")
			}
			inFilter = text == "*filter"
			if inFilter {
				if found {
					return "", fmt.Errorf("duplicate filter table")
				}
				found = true
			}
		} else if inFilter {
			if text == "COMMIT" {
				if position < 0 {
					position = offset
				}
				inFilter = false
			} else if strings.HasPrefix(text, ":") {
				if position >= 0 {
					return "", fmt.Errorf("chain declaration after rules")
				}
				if strings.Fields(text)[0] == ":"+chain {
					declared = true
				}
			} else if text != "" && !strings.HasPrefix(text, "#") && position < 0 {
				position = offset
			}
		}
		offset += len(line)
	}
	if !found || inFilter || !declared || position < 0 {
		return "", fmt.Errorf("invalid filter table or missing %s", chain)
	}
	return content[:position] + strings.TrimSpace(block) + "\n" + content[position:], nil
}
