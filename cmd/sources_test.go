package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/Flecksis/rkn-guard/internal/service"
)

func TestDisplaySources(t *testing.T) {
	state := &service.SourceState{
		Extra: []service.ExtraSource{{ID: 3, URL: "https://example.org/list", Enabled: true}, {ID: 7, URL: "https://example.org/empty"}},
		Cache: map[string]service.SourceCache{
			"https://example.org/list": {Networks: []string{"192.0.2.0/24"}, UpdatedAt: "2026-11-07T18:02:15Z", LastError: "ошибка загрузки"},
		},
	}
	file, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	stdout := os.Stdout
	os.Stdout = file
	defer func() { os.Stdout = stdout }()
	displaySources(state)
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	output := string(data)
	for _, want := range []string{"Всего: 2 · Включено: 1", "3. ● включён", "7. ● выключен", "https://example.org/list", "Подсетей в копии: 1", "Обновлён: 07.11.2026 21:02:15 МСК", "Обновлён: нет данных", "Последняя ошибка: ошибка загрузки"} {
		if !strings.Contains(output, want) {
			t.Errorf("нет %q в выводе %q", want, output)
		}
	}
	if strings.Contains(output, "\033[") {
		t.Error("цвета попали в файл")
	}
}

func TestSourceUpdateTime(t *testing.T) {
	for _, test := range []struct{ input, want string }{
		{"2026-11-07T18:02:15Z", "07.11.2026 21:02:15 МСК"},
		{"2026-11-07T23:32:15.123+05:30", "07.11.2026 21:02:15 МСК"},
		{"2026-11-07T13:02:15-05:00", "07.11.2026 21:02:15 МСК"},
		{"2026-12-31T23:00:00Z", "01.01.2027 02:00:00 МСК"},
		{"", "нет данных"},
		{"bad", "нет данных"},
	} {
		t.Run(test.input, func(t *testing.T) {
			if got := sourceUpdateTime(test.input); got != test.want {
				t.Errorf("sourceUpdateTime(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}
