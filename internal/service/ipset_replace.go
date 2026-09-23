package service

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Flecksis/rkn-guard/internal/domain"
)

type setCommands interface {
	CreateHashNet(string, Family, int, int) error
	Add(string, string) error
	Exists(string) bool
	Swap(string, string) error
	Destroy(string) error
	Snapshot(string) (string, error)
}

// Replace stages both families before touching live sets. Swaps are atomic per
// family, not across families. On a later error we swap the old contents back.
func (s *IpsetService) Replace(networks *domain.NetworkList, path string) error {
	return replaceSets(s.ipsetCmd, networks, func(data []byte) error {
		return atomicWriteFile(path, data, 0600)
	})
}

func replaceSets(cmd setCommands, networks *domain.NetworkList, persist func([]byte) error) (result error) {
	if networks == nil || networks.TotalCount() == 0 {
		return fmt.Errorf("refusing empty replacement")
	}
	type stagedSet struct {
		live, temp               string
		family                   Family
		entries                  []string
		staged, created, swapped bool
	}
	sets := []stagedSet{
		{live: ipsetV4Name, temp: fmt.Sprintf("RKN-NEXT4-%d", os.Getpid()), family: FamilyIPv4, entries: networks.IPv4Subnets},
		{live: ipsetV6Name, temp: fmt.Sprintf("RKN-NEXT6-%d", os.Getpid()), family: FamilyIPv6, entries: networks.IPv6Subnets},
	}
	committed := false
	defer func() {
		for i := len(sets) - 1; i >= 0; i-- {
			set := &sets[i]
			if !committed && set.swapped {
				if err := cmd.Swap(set.temp, set.live); err != nil {
					result = errors.Join(result, fmt.Errorf("rollback failed; old contents retained in %s: %w", set.temp, err))
					continue // Keep the only copy of the old contents for recovery.
				}
			}
			if !committed && set.created {
				result = errors.Join(result, cmd.Destroy(set.live))
			}
			if set.staged {
				result = errors.Join(result, cmd.Destroy(set.temp))
			}
		}
	}()
	for i := range sets {
		set := &sets[i]
		if err := cmd.CreateHashNet(set.temp, set.family, 1024, 65536); err != nil {
			return err
		}
		set.staged = true
		for _, entry := range set.entries {
			if err := cmd.Add(set.temp, entry); err != nil {
				return fmt.Errorf("stage %s: %w", entry, err)
			}
		}
	}
	for i := range sets {
		set := &sets[i]
		if !cmd.Exists(set.live) {
			if err := cmd.CreateHashNet(set.live, set.family, 1024, 65536); err != nil {
				return err
			}
			set.created = true
		}
		if err := cmd.Swap(set.temp, set.live); err != nil {
			return err
		}
		set.swapped = true
	}
	var snapshot strings.Builder
	for _, set := range sets {
		data, err := cmd.Snapshot(set.live)
		if err != nil {
			return err
		}
		snapshot.WriteString(data)
	}
	if err := persist([]byte(snapshot.String())); err != nil {
		return err
	}
	committed = true
	return nil
}
