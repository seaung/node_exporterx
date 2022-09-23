package collector

import (
	"fmt"
	_ "net/http/pprof"
	"strconv"
	"strings"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/shirou/gopsutil/process"
	"gopkg.in/alecthomas/kingpin.v2"
)

// Version is set at build time use ldflags.
var (
	//apps = config.GlobalConfig.Apps
	Apps          []string
	maxProcessNum = kingpin.Flag("max.process.num", "maximum number of monitored process").Default("100").Int()
)

func init() {
	registerCollector("process", defaultEnabled, NewNamedProcessCollector)
}

type (
	NamedProcessCollector struct {
		numThreads *prometheus.Desc
		cpuPercent *prometheus.Desc
		membytes   *prometheus.Desc
		status     *prometheus.Desc
		logger     log.Logger
	}

	ProcessMetric struct {
		cpuPercent  float64
		mem         *process.MemoryInfoStat
		io          *process.IOCountersStat
		ctx         *process.NumCtxSwitchesStat
		page        *process.PageFaultsStat
		processName string
		processNum  int32
		startTime   int64
		gids        []int32
		uids        []int32
		pid         int32
		cmdLine     string
		status      bool
	}
)

func NewNamedProcessCollector(logger log.Logger) (Collector, error) {
	subsystem := "process"
	p := &NamedProcessCollector{
		numThreads: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "num_threads"),
			"number of thread in this process",
			[]string{"app", "gids", "uids", "pid", "path"}, ConstLabels),

		cpuPercent: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "cpu_percent"),
			"Cpu user usage in seconds",
			[]string{"app", "gids", "uids", "pid", "path"}, ConstLabels),
		membytes: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "memory_bytes"),
			"number of bytes of memory in use",
			[]string{"app", "gids", "uids", "memtype", "pid", "path"},
			ConstLabels),
		status: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "status"),
			"process status",
			[]string{"app"},
			ConstLabels,
		),
		logger: logger,
	}
	return p, nil
}

func (c *NamedProcessCollector) Update(ch chan<- prometheus.Metric) error {
	metrics := make([]ProcessMetric, 0)
	pids, _ := process.Pids()
	processList, unNormalApp := selectPids(pids, Apps)

	for _, pn := range processList {
		pName, _ := pn.Name()
		gids, _ := pn.Gids()
		uids, _ := pn.Uids()
		startTime, _ := pn.CreateTime()
		processNum, _ := pn.NumThreads()
		cpuPercent, _ := pn.CPUPercent()
		mem, _ := pn.MemoryInfo()
		ioc, _ := pn.IOCounters()
		ctx, _ := pn.NumCtxSwitches()
		page, _ := pn.PageFaults()
		cmdLine, _ := pn.Cmdline()
		metric := ProcessMetric{
			cpuPercent:  cpuPercent,
			mem:         mem,
			io:          ioc,
			ctx:         ctx,
			page:        page,
			processName: pName,
			processNum:  processNum,
			startTime:   startTime,
			gids:        gids,
			uids:        uids,
			pid:         pn.Pid,
			cmdLine:     cmdLine,
			status:      true,
		}
		metrics = append(metrics, metric)
	}
	if len(unNormalApp) > 0 {
		for _, app := range unNormalApp {
			metric := ProcessMetric{
				cpuPercent:  0,
				mem:         nil,
				processName: app,
				processNum:  0,
				startTime:   0,
				gids:        nil,
				uids:        nil,
				pid:         0,
				cmdLine:     "",
				status:      false,
			}
			metrics = append(metrics, metric)
		}
	}

	for _, metric := range metrics {
		pid := strconv.Itoa(int(metric.pid))
		if !metric.status {
			ch <- prometheus.MustNewConstMetric(c.numThreads,
				prometheus.GaugeValue, float64(metric.processNum), metric.processName, "", "", pid, metric.cmdLine)
			ch <- prometheus.MustNewConstMetric(c.cpuPercent,
				prometheus.GaugeValue, float64(metric.cpuPercent), metric.processName, "", "", pid, metric.cmdLine)
			ch <- prometheus.MustNewConstMetric(c.membytes,
				prometheus.GaugeValue, 0.0, metric.processName, "", "", "resident", pid, metric.cmdLine)
			ch <- prometheus.MustNewConstMetric(c.membytes,
				prometheus.GaugeValue, 0.0, metric.processName, "", "", "virtual", pid, metric.cmdLine)
			ch <- prometheus.MustNewConstMetric(c.membytes,
				prometheus.GaugeValue, 0.0, metric.processName, "", "", "swapped", pid, metric.cmdLine)
			ch <- prometheus.MustNewConstMetric(c.status,
				prometheus.GaugeValue, 0.0, metric.processName)
		} else {
			ch <- prometheus.MustNewConstMetric(c.numThreads,
				prometheus.GaugeValue, float64(metric.processNum), metric.processName, formatGuid(metric.gids), formatGuid(metric.uids), pid, metric.cmdLine)
			ch <- prometheus.MustNewConstMetric(c.cpuPercent,
				prometheus.GaugeValue, float64(metric.cpuPercent), metric.processName, formatGuid(metric.gids), formatGuid(metric.uids), pid, metric.cmdLine)
			ch <- prometheus.MustNewConstMetric(c.membytes,
				prometheus.GaugeValue, float64(metric.mem.RSS), metric.processName, formatGuid(metric.gids), formatGuid(metric.uids), "resident", pid, metric.cmdLine)
			ch <- prometheus.MustNewConstMetric(c.membytes,
				prometheus.GaugeValue, float64(metric.mem.VMS), metric.processName, formatGuid(metric.gids), formatGuid(metric.uids), "virtual", pid, metric.cmdLine)
			ch <- prometheus.MustNewConstMetric(c.membytes,
				prometheus.GaugeValue, float64(metric.mem.Swap), metric.processName, formatGuid(metric.gids), formatGuid(metric.uids), "swapped", pid, metric.cmdLine)
			ch <- prometheus.MustNewConstMetric(c.status,
				prometheus.GaugeValue, 1.0, metric.processName)
		}
	}

	return nil
}

func formatGuid(ids []int32) string {
	tmp := make([]string, 0)
	idMap := make(map[int32]bool)
	for _, id := range ids {
		if _, ok := idMap[id]; ok {
			continue
		}
		idMap[id] = true
		tmp = append(tmp, fmt.Sprintf("%d", id))
	}
	return strings.Join(tmp, ",")
}

func selectPids(pids []int32, apps []string) ([]*process.Process, []string) {
	appMap := make(map[string]bool)
	unNormalApp := make([]string, 0)
	processList := make([]*process.Process, 0)
	for _, p := range pids {
		pn, _ := process.NewProcess(p)
		if len(apps) > 0 {
			pName, _ := pn.Name()
			for _, app := range apps {
				if strings.Contains(pName, app) {
					processList = append(processList, pn)
					appMap[app] = true
				}
			}
		} else {
			processList = append(processList, pn)
		}
	}
	for _, app := range apps {
		if _, ok := appMap[app]; !ok {
			unNormalApp = append(unNormalApp, app)
		}
	}

	if len(processList) >= *maxProcessNum {
		quickSort(processList, 0, len(processList)-1)
		return processList[:*maxProcessNum], unNormalApp
	}
	return processList, unNormalApp
}

func partSort(array []*process.Process, left, right int) int {
	tmp := array[right]
	tp, _ := tmp.CPUPercent()
	for left < right {
		lcp, _ := array[left].CPUPercent()
		for left < right && lcp >= tp {
			left++
		}
		array[right] = array[left]
		rcp, _ := array[right].CPUPercent()
		for left < right && rcp <= tp {
			right--
		}
		array[left] = array[right]
	}
	array[left] = tmp
	return left
}

func quickSort(array []*process.Process, left, right int) {
	if left >= right {
		return
	}
	mid := partSort(array, left, right)
	quickSort(array, left, mid-1)
	quickSort(array, mid+1, right)
}
