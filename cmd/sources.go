package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
	_ "time/tzdata"

	"github.com/Flecksis/rkn-guard/internal/domain"
	"github.com/Flecksis/rkn-guard/internal/logger"
	"github.com/Flecksis/rkn-guard/internal/service"
	"github.com/spf13/cobra"
)

var sourcesFile = service.SourcesPath
var managedLists bool

func sourceUpdateTime(value string) string {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return "нет данных"
	}
	moscow, err := time.LoadLocation("Europe/Moscow")
	if err != nil {
		return "нет данных"
	}
	return parsed.In(moscow).Format("02.01.2006 15:04:05") + " МСК"
}

func displaySources(state *service.SourceState) {
	info, err := os.Stdout.Stat()
	_, noColor := os.LookupEnv("NO_COLOR")
	color := err == nil && info.Mode()&os.ModeCharDevice != 0 && !noColor && os.Getenv("TERM") != "dumb"
	paint := func(value, style string) string {
		if color {
			return "\033[" + style + "m" + value + "\033[0m"
		}
		return value
	}
	enabled := 0
	for _, source := range state.Extra {
		if source.Enabled {
			enabled++
		}
	}
	fmt.Printf("Всего: %d · Включено: %d\n\n", len(state.Extra), enabled)
	if len(state.Extra) == 0 {
		fmt.Println("Дополнительные списки пока не добавлены.")
	}
	for _, source := range state.Extra {
		status, style := "выключен", "90"
		if source.Enabled {
			status, style = "включён", "32"
		}
		cache := state.Cache[source.URL]
		fmt.Printf("%d. %s\n", source.ID, paint("● "+status, style))
		fmt.Printf("   %s\n", paint(source.URL, "90"))
		fmt.Printf("   Подсетей в копии: %s · %s\n\n", paint(strconv.Itoa(len(cache.Networks)), "1;33"),
			paint("Обновлён: "+sourceUpdateTime(cache.UpdatedAt), "90"))
		if cache.LastError != "" {
			fmt.Printf("   %s\n\n", paint("Последняя ошибка: "+cache.LastError, "33"))
		}
	}
}

func sourceStore(downloader *service.Downloader) *service.SourceStore {
	return &service.SourceStore{Path: sourcesFile, Downloader: downloader}
}

func applySourceNetworks(ipsets *service.IpsetService, networks *domain.NetworkList) error {
	if networks.TotalCount() == 0 {
		logger.Global().Warn().Msg("Все источники отключены. Очищаем наборы rkn-guard, сохраняя правила пользователя.")
		return ipsets.Clear(service.IpsetConfigPath)
	}
	return ipsets.Replace(networks, service.IpsetConfigPath)
}

func downloadConfiguredLists(downloader *service.Downloader) (*domain.NetworkList, []string, error) {
	if !managedLists {
		networks, err := downloader.Download(urls)
		return networks, nil, err
	}
	networks, warnings, err := sourceStore(downloader).Download(urls)
	for _, warning := range warnings {
		logger.Global().Warn().Msg(warning)
	}
	return networks, warnings, err
}

func newSourcesCommand() *cobra.Command {
	var baseURLs []string
	command := &cobra.Command{
		Use:   "sources <list|add|enable|disable|remove|base-list|base-enable|base-disable> [URL или номер]",
		Short: "Настроить дополнительные списки подсетей",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := service.NewInstallerService(logger.Global().Logger).CheckRootPrivileges(); err != nil {
				return err
			}
			lock, err := service.AcquireLock()
			if err != nil {
				return fmt.Errorf("другая операция уже работает; попробуйте позже: %w", err)
			}
			defer lock.Close()
			store := sourceStore(service.NewDownloader(logger.Global().Logger))
			action := args[0]
			if action == "base-list" {
				if len(args) != 1 {
					return fmt.Errorf("просмотр не требует номера")
				}
				sources, err := store.BaseSources(baseURLs)
				if err != nil {
					return err
				}
				if len(sources) == 0 {
					fmt.Println("Базовые списки не заданы.")
				}
				for _, source := range sources {
					status := "Отключён"
					if source.Enabled {
						status = "Включён"
					}
					fmt.Printf("%d. ● %s\n   %s\n\n", source.ID, status, source.URL)
				}
				return nil
			}
			if action == "list" {
				if len(args) != 1 {
					return fmt.Errorf("просмотр списка не требует дополнительных аргументов")
				}
				state, err := store.Load()
				if err != nil {
					return err
				}
				displaySources(state)
				return nil
			}
			if len(args) != 2 {
				return fmt.Errorf("укажите URL для добавления или номер списка для изменения")
			}
			if action == "add" {
				id, err := store.Add(args[1], baseURLs)
				if err != nil {
					return fmt.Errorf("список не добавлен: %w", err)
				}
				fmt.Printf("Список %d проверен и сохранён. Пока выключен — включите его отдельно.\n", id)
				return nil
			}
			id, err := strconv.Atoi(args[1])
			if err != nil || id < 1 {
				return fmt.Errorf("номер списка должен быть положительным целым числом")
			}
			if action == "base-enable" || action == "base-disable" {
				err = store.ChangeBase(baseURLs, id, action == "base-enable")
			} else {
				err = store.Change(id, action)
			}
			if err != nil {
				return err
			}
			fmt.Println("Настройки сохранены. Для применения нужно обновить списки.")
			return nil
		},
	}
	command.Flags().StringArrayVar(&baseURLs, "base-url", nil, "Основной источник, который нельзя добавить второй раз")
	return command
}
