// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package compute

import (
	"testing"

<<<<<<< HEAD
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/genproto/googleapis/api/metric"
	"google.golang.org/genproto/googleapis/api/monitoredres"
	monitoring "google.golang.org/genproto/googleapis/monitoring/v3"
=======
	monitoring "cloud.google.com/go/monitoring/apiv3/v2/monitoringpb"
	"github.com/stretchr/testify/assert"
	"google.golang.org/genproto/googleapis/api/metric"
	"google.golang.org/genproto/googleapis/api/monitoredres"
	"google.golang.org/protobuf/types/known/timestamppb"
>>>>>>> b59a8f4769 (Replace EOL modules: github.com/golang/protobuf by google.golang.org/protobuf (#37212))
)

var fake = &monitoring.TimeSeries{
	Resource: &monitoredres.MonitoredResource{
		Type: "gce_instance",
		Labels: map[string]string{
			"instance_id": "4624337448093162893",
			"project_id":  "elastic-metricbeat",
			"zone":        "us-central1-a",
		},
	},
	Metadata: &monitoredres.MonitoredResourceMetadata{
		UserLabels: map[string]string{
			"user": "label",
		},
	},
	Metric: &metric.Metric{
		Labels: map[string]string{
			"instance_name": "instance-1",
		},
		Type: "compute.googleapis.com/instance/cpu/usage_time",
	},
	MetricKind: metric.MetricDescriptor_GAUGE,
	ValueType:  metric.MetricDescriptor_DOUBLE,
	Points: []*monitoring.Point{{
		Value: &monitoring.TypedValue{
			Value: &monitoring.TypedValue_DoubleValue{DoubleValue: 0.0041224284852319215},
		},
		Interval: &monitoring.TimeInterval{
			StartTime: &timestamppb.Timestamp{
				Seconds: 1569932700,
			},
			EndTime: &timestamppb.Timestamp{
				Seconds: 1569932700,
			},
		},
	}, {
		Value: &monitoring.TypedValue{
			Value: &monitoring.TypedValue_DoubleValue{DoubleValue: 0.004205757571772513},
		},
		Interval: &monitoring.TimeInterval{
			StartTime: &timestamppb.Timestamp{
				Seconds: 1569932640,
			},
			EndTime: &timestamppb.Timestamp{
				Seconds: 1569932640,
			},
		},
	}},
}

var m = &metadataCollector{
	projectID: "projectID",
}

func TestInstanceID(t *testing.T) {
	instanceID := m.instanceID(fake)
	assert.Equal(t, "4624337448093162893", instanceID)
}

func TestInstanceZone(t *testing.T) {
	zone := m.instanceZone(fake)
	assert.Equal(t, "us-central1-a", zone)
}
