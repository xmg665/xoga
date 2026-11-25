//go:build !linux

package panel

import "runtime"

func CollectSystemStatus() SystemStatus {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return SystemStatus{
		CPU:       1.0,
		MemTotal:  m.Sys,
		MemUsed:   m.Alloc,
		LoadAvg:   "0.01 0.01 0.01",
		UptimeSec: 60,
	}
}
