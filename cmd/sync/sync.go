package main

import (
	"flag"
	"io/ioutil"
	"log"
	"time"

	"github.com/ghodss/yaml"
	"github.com/openshift/openshift-azure/pkg/addons"
	acsapi "github.com/openshift/openshift-azure/pkg/api"
	"github.com/pkg/errors"
)

var (
	dryRun   = flag.Bool("dry-run", false, "Print resources to be synced instead of mutating cluster state.")
	once     = flag.Bool("run-once", false, "If true, run only once then quit.")
	interval = flag.Duration("interval", 3*time.Minute, "How often the sync process going to be rerun.")
)

func sync() error {
	log.Print("Sync process started!")

	b, err := ioutil.ReadFile("_data/containerservice.yaml")
	if err != nil {
		return errors.Wrap(err, "cannot read _data/containerservice.yaml")
	}

	var cs *acsapi.ContainerService
	if err := yaml.Unmarshal(b, &cs); err != nil {
		return errors.Wrap(err, "cannot unmarshal _data/containerservice.yaml")
	}

	if err := addons.Main(cs, *dryRun); err != nil {
		return errors.Wrap(err, "cannot sync cluster config")
	}

	log.Print("Sync process complete!")
	return nil
}

func main() {
	flag.Parse()

	for {
		if err := sync(); err != nil {
			log.Printf("Error while syncing: %v", err)
		}
		if *once {
			return
		}
		<-time.After(*interval)
	}
}
