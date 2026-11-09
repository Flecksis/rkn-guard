package service

import (
	"errors"
	"fmt"
	"os"
)

// Откатываем настройки при сбое. Журналы, CSV и позиции чтения не трогаем.
func (s *LoggingService) backupSettings() (func() error, error) {
	type savedFile struct {
		path   string
		data   []byte
		mode   os.FileMode
		exists bool
	}
	var files []savedFile
	for _, path := range []string{RsyslogConfigPath, LogrotateConfigPath, AggregateLogsScriptPath, AggregateLogsServicePath, AggregateLogsTimerPath} {
		path = s.path(path)
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			files = append(files, savedFile{path: path})
			continue
		}
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		files = append(files, savedFile{path, data, info.Mode().Perm(), true})
	}
	return func() error {
		var result error
		for _, file := range files {
			var err error
			if file.exists {
				err = atomicWriteFile(file.path, file.data, file.mode)
			} else {
				err = os.Remove(file.path)
				if os.IsNotExist(err) {
					err = nil
				}
			}
			if err != nil {
				result = errors.Join(result, fmt.Errorf("откат %s: %w", file.path, err))
			}
		}
		return result
	}, nil
}
