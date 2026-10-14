package main

import (
	"fmt"
	"strconv"

	"github.com/Flecksis/rkn-guard/internal/domain"
	"github.com/Flecksis/rkn-guard/internal/logger"
	"github.com/Flecksis/rkn-guard/internal/service"
	"github.com/spf13/cobra"
)

var sourcesFile = service.SourcesPath
var managedLists bool

func sourceStore(downloader *service.Downloader) *service.SourceStore {
	return &service.SourceStore{Path: sourcesFile, Downloader: downloader}
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
		Use:   "sources <list|add|enable|disable|remove> [URL или номер]",
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
			if action == "list" {
				if len(args) != 1 {
					return fmt.Errorf("просмотр списка не требует дополнительных аргументов")
				}
				state, err := store.Load()
				if err != nil {
					return err
				}
				if len(state.Extra) == 0 {
					fmt.Println("Дополнительные списки пока не добавлены.")
				}
				for _, source := range state.Extra {
					status := "выключен"
					if source.Enabled {
						status = "включён"
					}
					cache := state.Cache[source.URL]
					fmt.Printf("%d. [%s] %s\n   Подсетей в копии: %d; проверена: %s\n", source.ID, status, source.URL, len(cache.Networks), cache.UpdatedAt)
					if cache.LastError != "" {
						fmt.Printf("   Последняя ошибка: %s\n", cache.LastError)
					}
				}
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
			if err := store.Change(id, action); err != nil {
				return err
			}
			fmt.Println("Настройки сохранены. Для применения нужно обновить списки.")
			return nil
		},
	}
	command.Flags().StringArrayVar(&baseURLs, "base-url", nil, "Основной источник, который нельзя добавить второй раз")
	return command
}
