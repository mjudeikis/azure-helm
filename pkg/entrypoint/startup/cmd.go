package startup

import (
	"github.com/spf13/cobra"

	"github.com/openshift/openshift-azure/pkg/entrypoint/config"
)

type cmdConfig struct {
	config.Common
	init bool
}

// NewCommand returns the cobra command for "startup".
func NewCommand() *cobra.Command {
	cc := &cobra.Command{
		Use:  "startup",
		Long: "Start startup application",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := configFromCmd(cmd)
			if err != nil {
				return err
			}
			return start(cfg)
		},
	}

	cc.Flags().Bool("init", false, "Whether to run the init code path for dns")

	return cc
}

func configFromCmd(cmd *cobra.Command) (*cmdConfig, error) {
	c := &cmdConfig{}
	var err error
	c.Common, err = config.CommonConfigFromCmd(cmd)
	if err != nil {
		return nil, err
	}
	return c, nil
}
