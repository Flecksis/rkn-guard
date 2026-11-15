package service

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Sentinel-ошибки preflight-проверок. Все они означают отказ ДО изменений:
// firewall, ipset и автозапуск остаются такими, какими были.
var (
	// ErrIpsetUnavailable — ipset не работает. На ноде без ipset `ufw reload`
	// может оставить политику INPUT DROP с нулём правил: это потеря SSH.
	ErrIpsetUnavailable = errors.New("ipset недоступен — установка прервана, firewall не изменён")
	// ErrMandatoryPortBlocked — план правил может отрезать обязательный порт.
	ErrMandatoryPortBlocked = errors.New("правило может отрезать обязательный порт — установка прервана, firewall не изменён")
	// ErrSSHUnverified — не удалось подтвердить, что SSH-порт слушается.
	ErrSSHUnverified = errors.New("не удалось подтвердить доступность SSH-порта — установка прервана, firewall не изменён")
)

// DefaultRequiredPorts — порты, которые обязаны остаться доступны на ноде.
//
//	22   — SSH (текущая сессия)
//	2222 — control-плоскость ноды (Remnawave node)
//	443, 2443, 2087 — точки входа VPN/подписки
//
// Список можно переопределить флагом --required-ports.
var DefaultRequiredPorts = []int{22, 2222, 443, 2443, 2087}

// DefaultSSHPorts — порты, по которым проверяется доступность SSH.
// 22 плюс фактический порт текущей сессии из SSH_CONNECTION.
var DefaultSSHPorts = []int{22}

type preflightCommands interface {
	Run(string, ...string) error
	RunOutput(string, ...string) (string, error)
}

// IpsetPreflight проверяет, что ipset реально работает, ДО любых изменений firewall.
//
// Проверяются три условия:
//  1. бинарник ipset есть в PATH;
//  2. модуль ядра ip_set загружен или загружается (lsmod/modprobe);
//  3. набор hash:net создаётся и удаляется — функциональная проверка.
//
// Функциональная проба — решающая: ip_set может быть вкомпилирован в ядро и не
// попадать в lsmod, поэтому отсутствие строки в lsmod само по себе не отказ.
// Но если проба не прошла, в ошибке перечисляются все три состояния.
func IpsetPreflight(cmd preflightCommands, commandExists func(string) bool) error {
	if cmd == nil {
		return fmt.Errorf("%w: нет исполнителя команд", ErrIpsetUnavailable)
	}
	if commandExists == nil || !commandExists("ipset") {
		return fmt.Errorf("%w: не найден бинарник ipset (apt-get install -y ipset)", ErrIpsetUnavailable)
	}

	moduleState := ipsetModuleState(cmd, commandExists)

	probe := fmt.Sprintf("RKN-PREFLIGHT-%d", os.Getpid())
	if err := cmd.Run("ipset", "create", probe, "hash:net", "family", "inet", "maxelem", "8"); err != nil {
		return fmt.Errorf("%w: пробный набор %s не создан (%v); модуль ядра: %s", ErrIpsetUnavailable, probe, err, moduleState)
	}
	if err := cmd.Run("ipset", "destroy", probe); err != nil {
		// Набор-проба остался: это не меняет firewall, но и молчать нельзя.
		return fmt.Errorf("%w: пробный набор %s не удалён (%v); модуль ядра: %s", ErrIpsetUnavailable, probe, err, moduleState)
	}
	return nil
}

// ipsetModuleState описывает состояние модуля ядра ip_set для логов и ошибок.
func ipsetModuleState(cmd preflightCommands, commandExists func(string) bool) string {
	if out, err := cmd.RunOutput("lsmod"); err == nil {
		if strings.Contains(strings.ReplaceAll(out, "-", "_"), "ip_set") {
			return "загружен (lsmod)"
		}
	}
	if commandExists != nil && commandExists("modprobe") {
		if err := cmd.Run("modprobe", "ip_set"); err == nil {
			return "загружен через modprobe"
		}
		return "не загружен (modprobe ip_set не сработал)"
	}
	return "не загружен, modprobe недоступен"
}

// PortStatus — состояние одного обязательного порта.
type PortStatus struct {
	Port      int
	Listening bool
	Address   string
}

// PortReport — что установщик признал обязательным и что реально слушается.
type PortReport struct {
	Mandatory []PortStatus
}

// ProtectedPorts возвращает обязательные порты, которые реально слушаются.
func (r PortReport) ProtectedPorts() []int {
	var ports []int
	for _, st := range r.Mandatory {
		if st.Listening {
			ports = append(ports, st.Port)
		}
	}
	return ports
}

// String печатает отчёт одной строкой: «22=listen(0.0.0.0) 443=absent».
func (r PortReport) String() string {
	parts := make([]string, 0, len(r.Mandatory))
	for _, st := range r.Mandatory {
		if st.Listening {
			parts = append(parts, fmt.Sprintf("%d=listen(%s)", st.Port, st.Address))
			continue
		}
		parts = append(parts, fmt.Sprintf("%d=absent", st.Port))
	}
	return strings.Join(parts, " ")
}

// ParseSSListeners разбирает вывод `ss -lntup` в карту «порт -> локальный адрес».
//
// Берётся только состояние LISTEN: пара «local:port» + peer «*». Адрес сохраняется,
// чтобы в логе было видно, слушается ли порт на всех интерфейсах (0.0.0.0 / ::)
// или только на localhost.
func ParseSSListeners(output string) map[int]string {
	listeners := map[int]string{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if !strings.HasSuffix(fields[i+1], ":*") {
				continue
			}
			addr, port, ok := splitListenAddress(fields[i])
			if !ok {
				continue
			}
			if _, seen := listeners[port]; !seen {
				listeners[port] = addr
			}
			break
		}
	}
	return listeners
}

// splitListenAddress разбирает «0.0.0.0:22», "*:22», «[::]:22», «127.0.0.1:53».
func splitListenAddress(token string) (string, int, bool) {
	idx := strings.LastIndex(token, ":")
	if idx < 0 {
		return "", 0, false
	}
	addr, portText := token[:idx], token[idx+1:]
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	addr = strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
	if addr == "" {
		addr = "*"
	}
	return addr, port, true
}

// CheckMandatoryPorts строит отчёт по обязательным портам и отказывает, если ни
// один SSH-порт не слушается: без этого нельзя доказать, что доступ сохранится.
func CheckMandatoryPorts(mandatory, sshPorts []int, ssOutput string) (PortReport, error) {
	mandatory = NormalizePorts(mandatory)
	if len(mandatory) == 0 {
		return PortReport{}, errors.New("пустой список обязательных портов")
	}
	listeners := ParseSSListeners(ssOutput)
	report := PortReport{Mandatory: make([]PortStatus, 0, len(mandatory))}
	for _, port := range mandatory {
		addr, ok := listeners[port]
		report.Mandatory = append(report.Mandatory, PortStatus{Port: port, Listening: ok, Address: addr})
	}
	sshOK := false
	for _, port := range NormalizePorts(sshPorts) {
		if _, ok := listeners[port]; ok {
			sshOK = true
			break
		}
	}
	if !sshOK {
		return report, fmt.Errorf("%w: в `ss -lntup` нет ни одного SSH-порта из %v", ErrSSHUnverified, NormalizePorts(sshPorts))
	}
	return report, nil
}

// RulesMayBlockMandatoryPorts возвращает правила, которые могут отрезать
// обязательные порты. Правило считается безопасным, если DROP/REJECT привязан к
// нашему ipset (`-m set --match-set ...`): оно бьёт только по адресам сканеров.
//
// DROP/REJECT без привязки к набору и без --dport — это и есть default-deny,
// из-за которого на ноде с единственным разрешением SSH пропадает доступ.
func RulesMayBlockMandatoryPorts(rules [][]string, mandatory []int) []string {
	mandatory = NormalizePorts(mandatory)
	var unsafe []string
	for _, rule := range rules {
		target := ""
		for i := 0; i+1 < len(rule); i++ {
			if rule[i] == "-j" {
				target = rule[i+1]
				break
			}
		}
		switch strings.ToUpper(target) {
		case "DROP", "REJECT":
		default:
			continue
		}
		if ruleMatchesSet(rule) {
			continue
		}
		ports := ruleDestinationPorts(rule)
		if len(ports) == 0 {
			unsafe = append(unsafe, strings.Join(rule, " "))
			continue
		}
		if portsIntersect(ports, mandatory) {
			unsafe = append(unsafe, strings.Join(rule, " "))
		}
	}
	return unsafe
}

func ruleMatchesSet(rule []string) bool {
	for i := 0; i+1 < len(rule); i++ {
		if rule[i] == "--match-set" {
			return true
		}
	}
	return false
}

// ruleDestinationPorts разбирает --dport/--dports, включая диапазоны «8000:8100».
func ruleDestinationPorts(rule []string) [][2]int {
	var ports [][2]int
	for i := 0; i+1 < len(rule); i++ {
		if rule[i] != "--dport" && rule[i] != "--dports" {
			continue
		}
		for _, item := range strings.Split(rule[i+1], ",") {
			if from, to, ok := parsePortRange(item); ok {
				ports = append(ports, [2]int{from, to})
			}
		}
	}
	return ports
}

func parsePortRange(item string) (int, int, bool) {
	item = strings.TrimSpace(item)
	if item == "" {
		return 0, 0, false
	}
	if strings.Contains(item, ":") {
		parts := strings.SplitN(item, ":", 2)
		from, err1 := strconv.Atoi(parts[0])
		toText := parts[1]
		if toText == "" {
			toText = "65535"
		}
		to, err2 := strconv.Atoi(toText)
		if err1 != nil || err2 != nil || from > to {
			return 0, 0, false
		}
		return from, to, true
	}
	port, err := strconv.Atoi(item)
	if err != nil {
		return 0, 0, false
	}
	return port, port, true
}

func portsIntersect(ranges [][2]int, mandatory []int) bool {
	for _, r := range ranges {
		for _, port := range mandatory {
			if port >= r[0] && port <= r[1] {
				return true
			}
		}
	}
	return false
}

// NormalizePorts убирает дубликаты и сортирует порты.
func NormalizePorts(ports []int) []int {
	seen := map[int]bool{}
	out := make([]int, 0, len(ports))
	for _, port := range ports {
		if seen[port] {
			continue
		}
		seen[port] = true
		out = append(out, port)
	}
	sort.Ints(out)
	return out
}

// SSHPortsFromEnv возвращает 22 и фактический порт текущей SSH-сессии.
// SSH_CONNECTION = "<client ip> <client port> <server ip> <server port>".
func SSHPortsFromEnv(getenv func(string) string) []int {
	ports := append([]int{}, DefaultSSHPorts...)
	if getenv == nil {
		return NormalizePorts(ports)
	}
	fields := strings.Fields(getenv("SSH_CONNECTION"))
	if len(fields) == 4 {
		if port, err := strconv.Atoi(fields[3]); err == nil && port > 0 && port <= 65535 {
			ports = append(ports, port)
		}
	}
	return NormalizePorts(ports)
}
