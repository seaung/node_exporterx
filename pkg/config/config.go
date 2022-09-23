package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

var Cconfig *Config

type Config struct {
	Area  string   `yaml:"area"`
	Apps  []string `yaml:"apps"`
	Paths []string `yaml:"paths"`
	Ports []string `yaml:"ports"`
	IP    string   `yaml:"ip"`
}

func InitConfig(path string) error {
	var cfg Config

	content, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(content, &cfg)
	if err != nil {
		return err
	}
	Cconfig = &cfg
	return nil
}
