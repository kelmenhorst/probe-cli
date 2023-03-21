package registry

//
// Registers the `fbmessenger' experiment.
//

import (
	"github.com/ooni/probe-cli/v3/internal/experiment/nfbmessenger"
	"github.com/ooni/probe-cli/v3/internal/model"
)

func init() {
	AllExperiments["nfacebook_messenger"] = &Factory{
		build: func(config interface{}) model.ExperimentMeasurer {
			return nfbmessenger.NewExperimentMeasurer(
				*config.(*nfbmessenger.Config),
			)
		},
		config:      &nfbmessenger.Config{},
		inputPolicy: model.InputNone,
	}
}
