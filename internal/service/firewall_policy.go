package service

import (
	"errors"
	"fmt"
	"strings"
)

// Sentinel-ошибки политики работы с firewall.
//
// rkn-guard не включает UFW и не меняет политику INPUT: включение firewall с
// единственным разрешением 22/tcp закрывает VPN-порты и ломает доступ к сервису.
// Если правила некуда поставить, установка завершается с ненулевым кодом и
// firewall остаётся нетронутым.
var (
	ErrUFWInactive = errors.New("UFW установлен, но выключен (Status: inactive)")
	ErrUFWNotReady = errors.New("не удалось определить состояние UFW")
)

// FirewallPlan описывает, что установщик собирается делать с firewall.
type FirewallPlan struct {
	// UFWPresent — в системе есть команда ufw.
	UFWPresent bool
	// UFWActive — UFW сейчас включён.
	UFWActive bool
	// ObserveOnly — включён режим только-наблюдения: firewall не меняется.
	ObserveOnly bool
}

// CanWriteRules сообщает, можно ли ставить правила в firewall.
func (p FirewallPlan) CanWriteRules() bool {
	if p.ObserveOnly {
		return false
	}
	if p.UFWPresent && !p.UFWActive {
		return false
	}
	return true
}

// PlanFirewall проверяет состояние firewall до любых изменений в системе.
//
// Правила:
//   - UFW отсутствует — правила ставятся напрямую в iptables (netfilter-persistent);
//   - UFW включён — правила добавляются в ufw-before-input и применяются reload'ом;
//   - UFW выключен — установка прерывается с ErrUFWInactive, firewall не меняется;
//   - observeOnly — изменения firewall запрещены, возвращается план без ошибки.
func PlanFirewall(cmd firewallCommands, commandExists func(string) bool, observeOnly bool) (FirewallPlan, error) {
	plan := FirewallPlan{ObserveOnly: observeOnly}
	if commandExists == nil || !commandExists("ufw") {
		return plan, nil
	}
	plan.UFWPresent = true

	status, err := cmd.RunOutput("ufw", "status")
	if err != nil {
		return plan, fmt.Errorf("%w: %v", ErrUFWNotReady, err)
	}
	plan.UFWActive = strings.Contains(status, "Status: active")

	if observeOnly {
		return plan, nil
	}
	if !plan.UFWActive {
		return plan, fmt.Errorf(
			"%w. rkn-guard не включает firewall автоматически: включение UFW с политикой DROP "+
				"и единственным правилом SSH закрыло бы VPN-порты. Разрешите нужные порты "+
				"(ufw allow <vpn-port>/tcp) и включите UFW вручную либо удалите ufw. "+
				"Установка прервана, firewall не изменён", ErrUFWInactive)
	}
	return plan, nil
}
