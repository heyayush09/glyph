package monitoring

import (
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
)

type Metrics struct {
	TotalRequests    atomic.Uint64
	AuthFailures     atomic.Uint64
	UnauthorizedHits atomic.Uint64
	PerRouteCounts   sync.Map // map[string]*atomic.Uint64
}

var stats = &Metrics{}

func RecordRequest(route string) {
	stats.TotalRequests.Add(1)

	val, _ := stats.PerRouteCounts.LoadOrStore(route, new(atomic.Uint64))
	val.(*atomic.Uint64).Add(1)
}

func RecordAuthFailure() {
	stats.AuthFailures.Add(1)
}

func RecordUnauthorized() {
	stats.UnauthorizedHits.Add(1)
}

func GetSnapshot() map[string]any {
	perRoute := make(map[string]uint64)

	stats.PerRouteCounts.Range(func(k, v any) bool {
		route, ok1 := k.(string)
		counter, ok2 := v.(*atomic.Uint64)
		if ok1 && ok2 {
			perRoute[route] = counter.Load()
		}
		return true
	})

	return map[string]any{
		"total_requests":    stats.TotalRequests.Load(),
		"auth_failures":     stats.AuthFailures.Load(),
		"unauthorized_hits": stats.UnauthorizedHits.Load(),
		"per_route":         perRoute,
	}
}

func Handler(w http.ResponseWriter, r *http.Request) {
	snapshot := GetSnapshot()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snapshot)
}
