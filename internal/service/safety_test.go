package service

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Flecksis/rkn-guard/internal/domain"
	"github.com/rs/zerolog"
)

func TestDownloadRequiresEverySource(t *testing.T) {
	for _, body := range []string{"", "# empty\n", "<html>error</html>", "192.0.2.1\nbroken", "0.0.0.0/0", "::ffff:192.0.2.1", strings.Repeat(" ", maxListBytes+1)} {
		t.Run(fmt.Sprintf("length-%d", len(body)), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/good" {
					fmt.Fprintln(w, "192.0.2.1")
					return
				}
				fmt.Fprint(w, body)
			}))
			defer s.Close()
			if n, err := NewDownloader(zerolog.Nop()).Download([]string{s.URL + "/good", s.URL + "/bad"}); err == nil || n != nil {
				t.Fatal("accepted bad source")
			}
		})
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "unavailable", 503) }))
	defer s.Close()
	if _, err := NewDownloader(zerolog.Nop()).Download([]string{s.URL}); err == nil {
		t.Fatal("accepted HTTP error")
	}
	if _, err := NewDownloader(zerolog.Nop()).Download(nil); err == nil {
		t.Fatal("accepted no URLs")
	}
}

func TestDownloadCanonicalizesAndDeduplicates(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "\ufeff192.0.2.1 # host\n192.0.2.1/32\n198.51.100.7/24\n2001:db8::1\n")
	}))
	defer s.Close()
	n, err := NewDownloader(zerolog.Nop()).Download([]string{s.URL, s.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(n.IPv4Subnets, []string{"192.0.2.1/32", "198.51.100.0/24"}) || !reflect.DeepEqual(n.IPv6Subnets, []string{"2001:db8::1/128"}) {
		t.Fatalf("unexpected networks: %+v", n)
	}
}

type fakeSets struct {
	sets                                                map[string][]string
	failAdd, failSecondSwap, failRollback, failSnapshot bool
	swaps                                               int
}

func (f *fakeSets) CreateHashNet(n string, _ Family, _, _ int) error {
	if f.Exists(n) {
		return errors.New("exists")
	}
	f.sets[n] = []string{}
	return nil
}
func (f *fakeSets) Exists(n string) bool { _, ok := f.sets[n]; return ok }
func (f *fakeSets) Add(n, e string) error {
	if f.failAdd {
		return errors.New("add failed")
	}
	f.sets[n] = append(f.sets[n], e)
	return nil
}
func (f *fakeSets) Swap(a, b string) error {
	f.swaps++
	if (f.failSecondSwap && f.swaps == 2) || (f.failRollback && f.swaps == 3) {
		return errors.New("swap failed")
	}
	f.sets[a], f.sets[b] = f.sets[b], f.sets[a]
	return nil
}
func (f *fakeSets) Destroy(n string) error { delete(f.sets, n); return nil }
func (f *fakeSets) Snapshot(n string) (string, error) {
	if f.failSnapshot {
		return "", errors.New("save failed")
	}
	return n + ":" + strings.Join(f.sets[n], ",") + "\n", nil
}

func TestReplacementRollback(t *testing.T) {
	for _, failure := range []string{"add", "second-swap", "snapshot", "persist", "success"} {
		t.Run(failure, func(t *testing.T) {
			f := &fakeSets{sets: map[string][]string{ipsetV4Name: {"old4"}, ipsetV6Name: {"old6"}, "foreign": {"keep"}}, failAdd: failure == "add", failSecondSwap: failure == "second-swap", failSnapshot: failure == "snapshot"}
			saved := "old file"
			err := replaceSets(f, &domain.NetworkList{IPv4Subnets: []string{"new4"}, IPv6Subnets: []string{"new6"}}, func(data []byte) error {
				if failure == "persist" {
					return errors.New("disk full")
				}
				saved = string(data)
				return nil
			})
			want4, want6 := "old4", "old6"
			if failure == "success" {
				if err != nil {
					t.Fatal(err)
				}
				want4, want6 = "new4", "new6"
				if strings.Contains(saved, "foreign") {
					t.Fatal("saved unrelated set")
				}
			} else {
				if err == nil {
					t.Fatal("missing failure")
				}
				if saved != "old file" {
					t.Fatal("changed persistence")
				}
			}
			if len(f.sets) != 3 || f.sets[ipsetV4Name][0] != want4 || f.sets[ipsetV6Name][0] != want6 || f.sets["foreign"][0] != "keep" {
				t.Fatalf("unexpected state: %v", f.sets)
			}
		})
	}
}

func TestRollbackFailureRetainsRecoverySet(t *testing.T) {
	f := &fakeSets{sets: map[string][]string{ipsetV4Name: {"old4"}, ipsetV6Name: {"old6"}}, failSecondSwap: true, failRollback: true}
	err := replaceSets(f, &domain.NetworkList{IPv4Subnets: []string{"new4"}}, func([]byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "old contents retained") {
		t.Fatal(err)
	}
	found := false
	for n, entries := range f.sets {
		if strings.HasPrefix(n, "RKN-NEXT4-") && len(entries) == 1 && entries[0] == "old4" {
			found = true
		}
	}
	if !found {
		t.Fatal("lost recovery set")
	}
}

func TestAtomicWriteFailureKeepsDestination(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "destination")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "old"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(target, []byte("new"), 0600); err == nil {
		t.Fatal("expected rename failure")
	}
	if data, err := os.ReadFile(filepath.Join(target, "old")); err != nil || string(data) != "keep" {
		t.Fatal("lost original")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("temporary file leaked")
	}
}

type fakeFirewall struct {
	calls  []string
	fail   bool
	status string
}

func (f *fakeFirewall) Run(name string, args ...string) error {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if f.fail {
		return errors.New("synthetic failure")
	}
	return nil
}
func (f *fakeFirewall) RunOutput(string, ...string) (string, error) { return f.status, nil }
func TestApplyUFW(t *testing.T) {
	for _, active := range []bool{true, false} {
		for _, fail := range []bool{true, false} {
			f := &fakeFirewall{fail: fail, status: "Status: active"}
			err := applyUFW(f, active)
			if (err != nil) != fail {
				t.Fatalf("unexpected error %v", err)
			}
			want := "ufw reload"
			if !active {
				want = "ufw --force enable"
			}
			if !reflect.DeepEqual(f.calls, []string{want}) {
				t.Fatalf("unexpected commands: %v", f.calls)
			}
		}
	}
	if err := applyUFW(&fakeFirewall{status: "Status: inactive"}, true); err == nil {
		t.Fatal("accepted inactive firewall")
	}
}
