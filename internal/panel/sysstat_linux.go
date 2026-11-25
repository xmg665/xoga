//go:build linux

package panel

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	cpuMu      sync.Mutex
	prevTotal  uint64
	prevIdle   uint64
	cachedStat SystemStatus
	cachedAt   time.Time
)

// CollectSystemStatus reads /proc/stat, /proc/meminfo, /proc/loadavg, /proc/uptime, and statfs("/")
// directly on Linux with zero CGO and zero external gopsutil bloat, caching snapshots for 2s so
// multi-node workers polling at 120ms stagger share accurate CPU deltas without redundant syscalls.
func CollectSystemStatus() SystemStatus {
	cpuMu.Lock()
	defer cpuMu.Unlock()
	now := time.Now()
	if !cachedAt.IsZero() && now.Sub(cachedAt) < 2*time.Second {
		return cachedStat
	}
	var st SystemStatus
	st.CPU = readCPUPercentLocked()
	st.MemTotal, st.MemUsed, st.SwapTotal, st.SwapUsed = readMemInfo()
	st.DiskTotal, st.DiskUsed = readRootDisk()
	st.LoadAvg = readLoadAvg()
	st.UptimeSec = readUptime()
	cachedStat = st
	cachedAt = now
	return st
}

func readCPUPercentLocked() float64 {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return 0
	}
	fields := strings.Fields(sc.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0
	}
	var total, idle uint64
	for i := 1; i < len(fields); i++ {
		v, _ := strconv.ParseUint(fields[i], 10, 64)
		total += v
		if i == 4 || i == 5 { // idle + iowait
			idle += v
		}
	}

	dTotal := total - prevTotal
	dIdle := idle - prevIdle
	prevTotal = total
	prevIdle = idle
	if dTotal == 0 || dIdle > dTotal {
		return cachedStat.CPU
	}
	pct := float64(dTotal-dIdle) * 100.0 / float64(dTotal)
	if pct > 100 {
		pct = 100
	}
	return pct
}

func readMemInfo() (memTotal, memUsed, swapTotal, swapUsed uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()

	var memAvail, memFree, buffers, cached uint64
	var hasAvail bool
	var swapFree uint64

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) < 2 {
			continue
		}
		kb, _ := strconv.ParseUint(parts[1], 10, 64)
		val := kb * 1024
		switch parts[0] {
		case "MemTotal:":
			memTotal = val
		case "MemAvailable:":
			memAvail = val
			hasAvail = true
		case "MemFree:":
			memFree = val
		case "Buffers:":
			buffers = val
		case "Cached:":
			cached = val
		case "SwapTotal:":
			swapTotal = val
		case "SwapFree:":
			swapFree = val
		}
	}
	if hasAvail && memTotal >= memAvail {
		memUsed = memTotal - memAvail
	} else if memTotal >= memFree+buffers+cached {
		memUsed = memTotal - (memFree + buffers + cached)
	}
	if swapTotal >= swapFree {
		swapUsed = swapTotal - swapFree
	}
	return
}

func readRootDisk() (total, used uint64) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs("/", &fs); err != nil {
		return 0, 0
	}
	bsize := uint64(fs.Bsize)
	total = fs.Blocks * bsize
	free := fs.Bavail * bsize
	if total >= free {
		used = total - free
	}
	return
}

func readLoadAvg() string {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return "0.00 0.00 0.00"
	}
	fields := strings.Fields(string(b))
	if len(fields) >= 3 {
		return fields[0] + " " + fields[1] + " " + fields[2]
	}
	return "0.00 0.00 0.00"
}

func readUptime() uint64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) >= 1 {
		f, _ := strconv.ParseFloat(fields[0], 64)
		return uint64(f)
	}
	return 0
}
