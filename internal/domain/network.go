package domain

// Subnet represents a single IP subnet (CIDR notation)
type Subnet struct {
	CIDR   string
	IsIPv6 bool
}

// NetworkList represents a collection of subnets grouped by version
type NetworkList struct {
	IPv4Subnets []string
	IPv6Subnets []string
}

// NewNetworkList creates a new empty network list
func NewNetworkList() *NetworkList {
	return &NetworkList{
		IPv4Subnets: make([]string, 0),
		IPv6Subnets: make([]string, 0),
	}
}

// Add adds a subnet to the appropriate list
func (nl *NetworkList) Add(subnet string, isIPv6 bool) {
	if isIPv6 {
		nl.IPv6Subnets = append(nl.IPv6Subnets, subnet)
	} else {
		nl.IPv4Subnets = append(nl.IPv4Subnets, subnet)
	}
}

// IPv4Count returns the number of IPv4 subnets
func (nl *NetworkList) IPv4Count() int {
	return len(nl.IPv4Subnets)
}

// IPv6Count returns the number of IPv6 subnets
func (nl *NetworkList) IPv6Count() int {
	return len(nl.IPv6Subnets)
}

// TotalCount returns the total number of subnets
func (nl *NetworkList) TotalCount() int {
	return nl.IPv4Count() + nl.IPv6Count()
}
