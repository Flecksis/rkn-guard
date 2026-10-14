package service

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

type sourceFixture struct {
	mu     sync.Mutex
	body   map[string]string
	status map[string]int
	hits   map[string]int
	server *httptest.Server
	store  *SourceStore
}

func newSourceFixture(t *testing.T) *sourceFixture {
	t.Helper()
	f := &sourceFixture{body: map[string]string{}, status: map[string]int{}, hits: map[string]int{}}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits[r.URL.Path]++
		if code := f.status[r.URL.Path]; code != 0 {
			w.WriteHeader(code)
		}
		fmt.Fprint(w, f.body[r.URL.Path])
	}))
	t.Cleanup(f.server.Close)
	f.store = &SourceStore{Path: filepath.Join(t.TempDir(), "sources.json"), Downloader: NewDownloader(zerolog.Nop())}
	f.set("/base", "192.0.2.0/24\n", 0)
	f.set("/extra", "198.51.100.0/24\n2001:db8::/32\n", 0)
	return f
}

func (f *sourceFixture) set(path, body string, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.body[path], f.status[path] = body, status
}

func TestNormalizeSourceURL(t *testing.T) {
	cases := map[string]string{
		"https://github.com/C24Be/AS_Network_List/blob/main/blacklists/blacklist-v4.txt": "https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist-v4.txt",
		"https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public/skipa.list": "https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/main/public/skipa.list",
		"http://localhost:1234/list?q=1,2": "http://localhost:1234/list?q=1,2",
	}
	for input, want := range cases {
		got, err := NormalizeSourceURL(input)
		if err != nil || got != want {
			t.Fatalf("URL %q: %q, %v", input, got, err)
		}
	}
	for _, input := range []string{"", "file:///etc/passwd", "ftp://host/file", "https://", "https://u:p@host/list", "https://host/list#part", "https://host/\nlist", " https://host/list", "$(touch /tmp/test)", "--help"} {
		if _, err := NormalizeSourceURL(input); err == nil {
			t.Fatalf("принят неверный URL: %q", input)
		}
	}
}

func TestSourcesLifecycleAndRestart(t *testing.T) {
	f := newSourceFixture(t)
	base := []string{f.server.URL + "/base"}
	id, err := f.store.Add(f.server.URL+"/extra", base)
	if err != nil || id != 1 {
		t.Fatal(id, err)
	}
	if _, err := f.store.Add(base[0], base); err == nil {
		t.Fatal("добавлен основной источник")
	}
	if _, err := f.store.Add(f.server.URL+"/extra", base); err == nil {
		t.Fatal("добавлен повторный URL")
	}
	// Новый объект читает те же настройки и кеш, как после перезапуска программы.
	f.store = &SourceStore{Path: f.store.Path, Downloader: NewDownloader(zerolog.Nop())}
	for _, action := range []string{"disabled", "enable", "disable", "enable", "remove"} {
		if action != "disabled" {
			if err := f.store.Change(id, action); err != nil {
				t.Fatal(err)
			}
		}
		n, warnings, err := f.store.Download(base)
		if err != nil || len(warnings) != 0 {
			t.Fatal(err, warnings)
		}
		want := 1
		if action == "enable" {
			want = 3
		}
		if n.TotalCount() != want {
			t.Fatalf("%s: получено %d, нужно %d", action, n.TotalCount(), want)
		}
	}
	state, _ := f.store.Load()
	if len(state.Extra) != 0 || len(state.Cache) != 1 {
		t.Fatalf("удаление оставило данные: %+v", state)
	}
	id, err = f.store.Add(f.server.URL+"/extra", base)
	if err != nil || id != 2 {
		t.Fatal("номер удалённого источника использован повторно", id, err)
	}
	if err := f.store.Change(999, "enable"); err == nil {
		t.Fatal("принят несуществующий номер")
	}
}

func TestSourceErrorsKeepCacheAndRefreshOthers(t *testing.T) {
	for _, broken := range []string{"<html>error</html>", "198.51.100.9/32\nне CIDR", "192.0.2.1", "", "0.0.0.0/0", "::/0", "::ffff:192.0.2.1/128", "192.0.2.0/33", strings.Repeat("x", maxListBytes+1)} {
		t.Run(fmt.Sprintf("размер-%d", len(broken)), func(t *testing.T) {
			f := newSourceFixture(t)
			base := []string{f.server.URL + "/base"}
			id, err := f.store.Add(f.server.URL+"/extra", base)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.store.Change(id, "enable"); err != nil {
				t.Fatal(err)
			}
			before, _ := f.store.Load()
			f.set("/base", "203.0.113.0/24", 0)
			f.set("/extra", broken, 0)
			n, warnings, err := f.store.Download(base)
			if err != nil || len(warnings) != 1 || !strings.Contains(warnings[0], "последние корректные данные") {
				t.Fatal(err, warnings)
			}
			if !reflect.DeepEqual(sourceNetworks(n), []string{"198.51.100.0/24", "2001:db8::/32", "203.0.113.0/24"}) {
				t.Fatalf("неверный общий список: %+v", n)
			}
			after, _ := f.store.Load()
			if !reflect.DeepEqual(before.Cache[f.server.URL+"/extra"].Networks, after.Cache[f.server.URL+"/extra"].Networks) {
				t.Fatal("ошибка затёрла корректную копию")
			}
			f.set("/extra", "198.51.100.8/32", 0)
			if _, warnings, err := f.store.Download(base); err != nil || len(warnings) != 0 {
				t.Fatal("не удалось восстановиться после ошибки", err, warnings)
			}
			after, _ = f.store.Load()
			if after.Cache[f.server.URL+"/extra"].LastError != "" {
				t.Fatal("старая ошибка не сброшена")
			}
		})
	}
}

func TestUnavailableBaseAndMissingCache(t *testing.T) {
	f := newSourceFixture(t)
	base := []string{f.server.URL + "/base", f.server.URL + "/missing"}
	f.set("/missing", "", 503)
	n, warnings, err := f.store.Download(base)
	if err != nil || n.TotalCount() != 1 || len(warnings) != 1 || !strings.Contains(warnings[0], "источник пропущен") {
		t.Fatal(n, warnings, err)
	}
	f.set("/base", "", 404)
	f.set("/missing", "198.51.100.0/24", 0)
	n, warnings, err = f.store.Download(base)
	if err != nil || n.TotalCount() != 2 || len(warnings) != 1 {
		t.Fatal(n, warnings, err)
	}
	f.set("/missing", "", 503)
	if n, warnings, err = f.store.Download(base); err != nil || n.TotalCount() != 2 || len(warnings) != 2 {
		t.Fatal("недоступные источники не восстановлены из кеша", n, warnings, err)
	}
	state, _ := f.store.Load()
	state.Cache = map[string]SourceCache{}
	if err := f.store.save(state); err != nil {
		t.Fatal(err)
	}
	if n, _, err := f.store.Download(base); err == nil || n != nil {
		t.Fatal("допущена замена пустым списком")
	}
}

func TestSourceTimeoutAndBadAddDoNotChangeSettings(t *testing.T) {
	f := newSourceFixture(t)
	base := []string{f.server.URL + "/base"}
	if _, err := f.store.Add(f.server.URL+"/extra", base); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(f.store.Path)
	f.set("/bad", "192.0.2.0/24\nbroken", 0)
	if _, err := f.store.Add(f.server.URL+"/bad", base); err == nil {
		t.Fatal("неверный список добавлен")
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(80 * time.Millisecond)
		fmt.Fprint(w, "192.0.2.0/24")
	}))
	defer slow.Close()
	f.store.Downloader.httpClient.Timeout = 10 * time.Millisecond
	if _, err := f.store.Add(slow.URL, base); err == nil {
		t.Fatal("таймаут не сработал")
	}
	after, _ := os.ReadFile(f.store.Path)
	if string(before) != string(after) {
		t.Fatal("неудачное добавление изменило настройки")
	}
}

func TestCacheValidationAndCorruptSettings(t *testing.T) {
	f := newSourceFixture(t)
	base := []string{f.server.URL + "/base"}
	if _, _, err := f.store.Download(base); err != nil {
		t.Fatal(err)
	}
	state, _ := f.store.Load()
	state.Cache[base[0]] = SourceCache{Networks: []string{"0.0.0.0/0"}}
	if err := f.store.save(state); err != nil {
		t.Fatal(err)
	}
	f.set("/base", "", 503)
	if n, _, err := f.store.Download(base); err == nil || n != nil {
		t.Fatal("повреждённый кеш применён")
	}
	if err := os.WriteFile(f.store.Path, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.Download(base); err == nil {
		t.Fatal("повреждённые настройки приняты")
	}
	data, _ := os.ReadFile(f.store.Path)
	if string(data) != "{broken" {
		t.Fatal("повреждённый файл затёрт")
	}
}

func TestSourceSaveFailurePreventsApplication(t *testing.T) {
	f := newSourceFixture(t)
	// Создаём препятствие после чтения настроек, но до атомарного сохранения.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := os.Mkdir(f.store.Path, 0700); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		fmt.Fprint(w, "192.0.2.0/24")
	}))
	defer server.Close()
	if n, _, err := f.store.Download([]string{server.URL}); err == nil || n != nil || !strings.Contains(err.Error(), "не удалось сохранить") {
		t.Fatal("ошибка хранения не остановила применение")
	}
}

func TestDisabledSourcesAreNotFetchedAndOverlapIsKept(t *testing.T) {
	f := newSourceFixture(t)
	base := []string{f.server.URL + "/base"}
	f.set("/extra", "192.0.2.0/24\n198.51.100.0/24", 0)
	id, err := f.store.Add(f.server.URL+"/extra", base)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.Change(id, "enable"); err != nil {
		t.Fatal(err)
	}
	n, _, err := f.store.Download(base)
	if err != nil || n.TotalCount() != 2 {
		t.Fatal(n, err)
	}
	if err := f.store.Change(id, "disable"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	hits := f.hits["/extra"]
	f.mu.Unlock()
	n, _, err = f.store.Download(base)
	if err != nil || !reflect.DeepEqual(n.IPv4Subnets, []string{"192.0.2.0/24"}) {
		t.Fatal(n, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hits["/extra"] != hits {
		t.Fatal("выключенный источник загружался")
	}
}
