package domain

// Subnet хранит одну подсеть в записи CIDR.
type Subnet struct {
	CIDR   string
	IsIPv6 bool
}

// NetworkList хранит отдельные списки подсетей IPv4 и IPv6.
type NetworkList struct {
	IPv4Subnets []string
	IPv6Subnets []string
}

// NewNetworkList создаёт пустой список подсетей.
func NewNetworkList() *NetworkList {
	return &NetworkList{
		IPv4Subnets: make([]string, 0),
		IPv6Subnets: make([]string, 0),
	}
}

// Add добавляет подсеть в список нужной версии IP.
func (nl *NetworkList) Add(subnet string, isIPv6 bool) {
	if isIPv6 {
		nl.IPv6Subnets = append(nl.IPv6Subnets, subnet)
	} else {
		nl.IPv4Subnets = append(nl.IPv4Subnets, subnet)
	}
}

// IPv4Count возвращает число подсетей IPv4.
func (nl *NetworkList) IPv4Count() int {
	return len(nl.IPv4Subnets)
}

// IPv6Count возвращает число подсетей IPv6.
func (nl *NetworkList) IPv6Count() int {
	return len(nl.IPv6Subnets)
}

// TotalCount возвращает общее число подсетей.
func (nl *NetworkList) TotalCount() int {
	return nl.IPv4Count() + nl.IPv6Count()
}
