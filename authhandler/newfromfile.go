package authhandler

import (
	"errors"
	//"fmt"
	"io/ioutil"
	//"log"
	//"net/http"
	"os"

	"golang.org/x/net/context"

	"gopkg.in/yaml.v2"
)

/*

var DefaultConfigFilename = "config.yml"
var defaultOIDCAuth *SimpleOIDCAuth
var defaultContext context.Context
*/
type OidcConfig struct {
	ClientID     string
	ClientSecret string
	ProviderURL  string
}

type AppConfigFile struct {
	Openidc OidcConfig
}

func loadVerifyConfigFile(configFilename string) (AppConfigFile, error) {
	var config AppConfigFile
	if _, err := os.Stat(configFilename); os.IsNotExist(err) {
		err = errors.New("mising config file failure")
		return config, err
	}
	source, err := ioutil.ReadFile(configFilename)
	if err != nil {
		//panic(err)
		err = errors.New("cannot read config file")
		return config, err
	}
	err = yaml.Unmarshal(source, &config)
	if err != nil {
		err = errors.New("Cannot parse config file")
		return config, err
	}
	// TODO: ensure the contents are NOT empty or invalid
	return config, nil
}

func NewSimpleOIDCAuthFromConfig(configFilename *string, ctx *context.Context) (*SimpleOIDCAuth, error) {
	if configFilename == nil {
		configFilename = &DefaultConfigFilename
	}
	config, err := loadVerifyConfigFile(*configFilename)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		bctx := context.Background()
		ctx = &bctx
	}

	return NewSimpleOIDCAuth(ctx, config.Openidc.ClientID, config.Openidc.ClientSecret, config.Openidc.ProviderURL), nil
}
