// Copyright 2015 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !nonetdev
// +build linux freebsd openbsd dragonfly darwin

package collector

import (
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	netdevDeviceInclude    = kingpin.Flag("collector.netdev.device-include", "Regexp of net devices to include (mutually exclusive to device-exclude).").String()
	oldNetdevDeviceInclude = kingpin.Flag("collector.netdev.device-whitelist", "DEPRECATED: Use collector.netdev.device-include").Hidden().String()
	netdevDeviceExclude    = kingpin.Flag("collector.netdev.device-exclude", "Regexp of net devices to exclude (mutually exclusive to device-include).").String()
	oldNetdevDeviceExclude = kingpin.Flag("collector.netdev.device-blacklist", "DEPRECATED: Use collector.netdev.device-exclude").Hidden().String()
)

type HistoryData struct {
	data []uint64
	pos  int
	lock sync.Mutex
}

func NewHistoryData(size int) *HistoryData {
	return &HistoryData{
		data: make([]uint64, size),
		pos:  0,
	}
}

func (d *HistoryData) Append(val uint64) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.data[d.pos] = val
	d.pos++
	if d.pos >= len(d.data) {
		d.pos = 0
	}
}

func (d *HistoryData) Max() uint64 {
	d.lock.Lock()
	defer d.lock.Unlock()
	max := uint64(0)
	for _, val := range d.data {
		if val > max {
			max = val
		}
	}
	return max
}

type netDevCollector struct {
	subsystem            string
	deviceExcludePattern *regexp.Regexp
	deviceIncludePattern *regexp.Regexp
	metricDescs          map[string]*prometheus.Desc
	logger               log.Logger
	bwSendHistory        map[string]*HistoryData
	bwRecvHistory        map[string]*HistoryData
	prevSendBytes        map[string]uint64
	prevRecvBytes        map[string]uint64
	historySize          int
	duration             int
}

type netDevStats map[string]map[string]uint64

func init() {
	registerCollector("netdev", defaultEnabled, NewNetDevCollector)
}

// NewNetDevCollector returns a new Collector exposing network device stats.
func NewNetDevCollector(logger log.Logger) (Collector, error) {
	if *oldNetdevDeviceInclude != "" {
		if *netdevDeviceInclude == "" {
			level.Warn(logger).Log("msg", "--collector.netdev.device-whitelist is DEPRECATED and will be removed in 2.0.0, use --collector.netdev.device-include")
			*netdevDeviceInclude = *oldNetdevDeviceInclude
		} else {
			return nil, errors.New("--collector.netdev.device-whitelist and --collector.netdev.device-include are mutually exclusive")
		}
	}

	if *oldNetdevDeviceExclude != "" {
		if *netdevDeviceExclude == "" {
			level.Warn(logger).Log("msg", "--collector.netdev.device-blacklist is DEPRECATED and will be removed in 2.0.0, use --collector.netdev.device-exclude")
			*netdevDeviceExclude = *oldNetdevDeviceExclude
		} else {
			return nil, errors.New("--collector.netdev.device-blacklist and --collector.netdev.device-exclude are mutually exclusive")
		}
	}

	if *netdevDeviceExclude != "" && *netdevDeviceInclude != "" {
		return nil, errors.New("device-exclude & device-include are mutually exclusive")
	}

	var excludePattern *regexp.Regexp
	if *netdevDeviceExclude != "" {
		level.Info(logger).Log("msg", "Parsed flag --collector.netdev.device-exclude", "flag", *netdevDeviceExclude)
		excludePattern = regexp.MustCompile(*netdevDeviceExclude)
	}

	var includePattern *regexp.Regexp
	if *netdevDeviceInclude != "" {
		level.Info(logger).Log("msg", "Parsed Flag --collector.netdev.device-include", "flag", *netdevDeviceInclude)
		includePattern = regexp.MustCompile(*netdevDeviceInclude)
	}

	ret := &netDevCollector{
		subsystem:            "network",
		deviceExcludePattern: excludePattern,
		deviceIncludePattern: includePattern,
		metricDescs:          map[string]*prometheus.Desc{},
		logger:               logger,
		bwSendHistory:        map[string]*HistoryData{},
		bwRecvHistory:        map[string]*HistoryData{},
		prevSendBytes:        map[string]uint64{},
		prevRecvBytes:        map[string]uint64{},
		historySize:          20,
		duration:             3,
	}
	go ret.RunMaxBandwidthCollect(logger)
	return ret, nil
}

func (c *netDevCollector) Update(ch chan<- prometheus.Metric) error {
	netDev, err := getNetDevStats(c.deviceExcludePattern, c.deviceIncludePattern, c.logger)
	if err != nil {
		return fmt.Errorf("couldn't get netstats: %w", err)
	}
	for dev, devStats := range netDev {
		for key, value := range devStats {
			desc, ok := c.metricDescs[key]
			if !ok {
				desc = prometheus.NewDesc(
					prometheus.BuildFQName(namespace, c.subsystem, key+"_total"),
					fmt.Sprintf("Network device statistic %s.", key),
					[]string{"device"},
					nil,
				)
				c.metricDescs[key] = desc
			}
			ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, float64(value), dev)
		}
	}
	for dev, bwRecvHist := range c.bwRecvHistory {
		bw := bwRecvHist.Max()
		key := "receive_max_bandwidth"
		desc, ok := c.metricDescs[key]
		if !ok {
			desc = prometheus.NewDesc(
				prometheus.BuildFQName(namespace, c.subsystem, key),
				fmt.Sprintf("Network device statistic %s.", key),
				[]string{"device"},
				nil,
			)
			c.metricDescs[key] = desc
		}
		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, float64(bw), dev)
	}
	for dev, bwSendHist := range c.bwSendHistory {
		bw := bwSendHist.Max()
		key := "transmit_max_bandwidth"
		desc, ok := c.metricDescs[key]
		if !ok {
			desc = prometheus.NewDesc(
				prometheus.BuildFQName(namespace, c.subsystem, key),
				fmt.Sprintf("Network device statistic %s.", key),
				[]string{"device"},
				nil,
			)
			c.metricDescs[key] = desc
		}
		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, float64(bw), dev)
	}
	return nil
}

func (c *netDevCollector) RunMaxBandwidthCollect(logger log.Logger) {
	err := c.getNetworkBandwidth(false)
	if err != nil {
		level.Error(logger).Log("msg", "Max bandwidth collector failed", "err", err)
	}
	for {
		time.Sleep(time.Duration(c.duration) * time.Second)
		err = c.getNetworkBandwidth(true)
		if err != nil {
			level.Error(logger).Log("msg", "Max bandwidth collector failed", "err", err)
		}
	}
}

func (c *netDevCollector) getNetworkBandwidth(calculateMax bool) error {
	netDev, err := getNetDevStats(c.deviceExcludePattern, c.deviceIncludePattern, c.logger)
	if err != nil {
		return fmt.Errorf("couldn't get netstats: %w", err)
	}
	for dev, devStats := range netDev {
		recvBytes, have := devStats["receive_bytes"]
		if !have {
			continue
		}
		sendBytes, have := devStats["transmit_bytes"]
		if !have {
			continue
		}
		recvBandwidth, sendBandwidth := c.calculateBandwidth(dev, recvBytes, sendBytes)
		if calculateMax {
			c.updateDeviceBandwidth(dev, recvBandwidth, sendBandwidth)
		}
	}
	return nil
}

func (c *netDevCollector) calculateBandwidth(dev string, recvBytes, sendBytes uint64) (recvBw uint64, sendBw uint64) {
	prevRecv, have := c.prevRecvBytes[dev]
	if have {
		recvBw = (recvBytes - prevRecv) / uint64(c.duration)
	} else {
		recvBw = 0
	}

	prevSend, have := c.prevSendBytes[dev]
	if have {
		sendBw = (sendBytes - prevSend) / uint64(c.duration)
	} else {
		sendBw = 0
	}

	c.prevRecvBytes[dev] = recvBytes
	c.prevSendBytes[dev] = sendBytes
	return
}

func (c *netDevCollector) updateDeviceBandwidth(dev string, recvBandwidth, sendBandwidth uint64) {
	recvHist, have := c.bwRecvHistory[dev]
	if have {
		recvHist.Append(recvBandwidth)
	} else {
		newRecvHist := NewHistoryData(c.historySize)
		newRecvHist.Append(recvBandwidth)
		c.bwRecvHistory[dev] = newRecvHist
	}
	sendHist, have := c.bwSendHistory[dev]
	if have {
		sendHist.Append(sendBandwidth)
	} else {
		newSendHist := NewHistoryData(c.historySize)
		newSendHist.Append(sendBandwidth)
		c.bwSendHistory[dev] = newSendHist
	}
}
