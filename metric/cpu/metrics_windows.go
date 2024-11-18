// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

/*
For testing via the win2012 vagrant box:
vagrant winrm -s cmd -e -c "cd C:\\Gopath\src\\github.com\\elastic\\beats\\metricbeat\\module\\system\\cpu; go test -v -tags=integration -run TestFetch"  win2012
*/

package cpu

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/elastic/elastic-agent-libs/helpers/windows/pdh"
	"github.com/elastic/elastic-agent-libs/opt"
	"github.com/elastic/elastic-agent-system-metrics/metric/system/resolve"
	"github.com/elastic/gosigar/sys/windows"
)

var (
	kernelTimeCounter = "\\Processor Information(_Total)\\% Privileged Time"
	userTimeCounter   = "\\Processor Information(_Total)\\% User Time"
	idleTimeCounter   = "\\Processor Information(_Total)\\% Idle Time"

	allCPUCounter = "\\Processor Information(*)\\*"
)

// Get fetches Windows CPU system times
func Get(_ resolve.Resolver) (CPUMetrics, error) {
	var q pdh.Query
	if err := q.Open(); err != nil {
		return CPUMetrics{}, fmt.Errorf("call to PdhOpenQuery failed: %w", err)
	}
	kernel, err := q.GetRawCounterValue(kernelTimeCounter)
	if err != nil {
		return CPUMetrics{}, fmt.Errorf("error getting Privileged Time counter: %w", err)
	}
	idle, err := q.GetRawCounterValue(idleTimeCounter)
	if err != nil {
		return CPUMetrics{}, fmt.Errorf("error getting Idle Time counter: %w", err)
	}
	user, err := q.GetRawCounterValue(userTimeCounter)
	if err != nil {
		return CPUMetrics{}, fmt.Errorf("error getting Privileged User counter: %w", err)
	}

	//convert from duration to ticks
	idleMetric := uint64(time.Duration(idle.FirstValue*100) / time.Millisecond)
	sysMetric := uint64(time.Duration(kernel.FirstValue*100) / time.Millisecond)
	userMetrics := uint64(time.Duration(user.FirstValue*100) / time.Millisecond)
	globalMetrics := CPUMetrics{}
	globalMetrics.totals.Idle = opt.UintWith(idleMetric)
	globalMetrics.totals.Sys = opt.UintWith(sysMetric)
	globalMetrics.totals.User = opt.UintWith(userMetrics)

	// get per-cpu data

	// try getting data via performance counters
	globalMetrics.list, err = populatePerCpuMetrics(&q)
	if err != nil {
		// this shouldn'r really fail but if it does, fallback to _NtQuerySystemInformation
		// _NtQuerySystemInformation return per-cpu data for current processor group i.e. upto 64 cores
		globalMetrics.list, err = populatePerCpuMetricsFallback()
		if err != nil {
			return CPUMetrics{}, fmt.Errorf("error getting per-cpu metrics: %w", err)
		}
	}
	return globalMetrics, nil
}

func populatePerCpuMetrics(q *pdh.Query) ([]CPU, error) {
	cpuMap := make(map[string]*CPU, runtime.NumCPU())
	counters, err := q.GetCounterPaths(allCPUCounter)
	if err != nil {
		return nil, fmt.Errorf("call to GetCounterPaths failed: %w", err)
	}
	for _, counter := range counters {
		instance, err := pdh.MatchInstanceName(counter)
		if err != nil {
			// invalid counter - ignore the error
			continue
		}
		if strings.Contains(strings.ToLower(instance), "_total") {
			continue
		}
		if _, ok := cpuMap[instance]; !ok {
			cpuMap[instance] = &CPU{}
		}
		val, err := q.GetRawCounterValue(counter)
		if err != nil {
			continue
		}
		valUint := uint64(time.Duration(val.FirstValue*100) / time.Millisecond)

		if strings.Contains(strings.ToLower(counter), "% idle time") {
			cpuMap[instance].Idle = opt.UintWith(valUint)
		} else if strings.Contains(strings.ToLower(counter), "% privileged time") {
			cpuMap[instance].Sys = opt.UintWith(valUint)
		} else if strings.Contains(strings.ToLower(counter), "% user time") {
			cpuMap[instance].User = opt.UintWith(valUint)
		}
	}

	list := make([]CPU, 0, len(cpuMap))
	for _, cpu := range cpuMap {
		list = append(list, *cpu)
	}
	return list, nil
}

func populatePerCpuMetricsFallback() ([]CPU, error) {
	cpus, err := windows.NtQuerySystemProcessorPerformanceInformation()
	if err != nil {
		return nil, fmt.Errorf("catll to NtQuerySystemProcessorPerformanceInformation failed: %w", err)
	}
	list := make([]CPU, 0, len(cpus))
	for _, cpu := range cpus {
		idleMetric := uint64(cpu.IdleTime / time.Millisecond)
		sysMetric := uint64(cpu.KernelTime / time.Millisecond)
		userMetrics := uint64(cpu.UserTime / time.Millisecond)
		list = append(list, CPU{
			Idle: opt.UintWith(idleMetric),
			Sys:  opt.UintWith(sysMetric),
			User: opt.UintWith(userMetrics),
		})
	}
	return list, nil
}
