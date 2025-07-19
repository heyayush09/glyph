package config

import (
	"log"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

type AtomicConfig struct {
	value atomic.Value
}

func NewAtomicConfig(c *Config) *AtomicConfig {
	ac := &AtomicConfig{}
	ac.Store(c)
	return ac
}

func (ac *AtomicConfig) Load() *Config {
	return ac.value.Load().(*Config)
}

func (ac *AtomicConfig) Store(c *Config) {
	ac.value.Store(c)
}

func WatchConfigFile(file string, ac *AtomicConfig) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("Failed to create watcher: %v", err)
	}
	defer watcher.Close()

	go func() {
		var debounce <-chan time.Time
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
					debounce = time.After(500 * time.Millisecond)
				}
			case <-debounce:
				newAtomicConfig, err := LoadConfig(file)
				if err != nil {
					log.Printf("[config] Failed to reload: %v", err)
					continue
				}
				newConfig := newAtomicConfig.Load()
				ac.Store(newConfig)
				log.Println("[config] Reloaded config.yaml")
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("Watcher error: %v", err)
			}
		}
	}()

	if err := watcher.Add(file); err != nil {
		log.Fatalf("Failed to watch file %s: %v", file, err)
	}
	<-make(chan struct{}) // block forever
}