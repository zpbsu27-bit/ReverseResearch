package server

import (
	"encoding/json"
	"net/http"
	"sync/atomic"

	"reverseresearch/internal/consolelog"
)

var httpWriteFailures atomic.Uint64

// httpWriteFailureLogEvery keeps a persistently broken client connection from
// turning every response into another stderr line under unattended operation.
const httpWriteFailureLogEvery = 1000

func reportHTTPWriteFailure(kind string, err error) {
	count := httpWriteFailures.Add(1)
	if count == 1 || count%httpWriteFailureLogEvery == 0 {
		consolelog.Eventf(consolelog.ColorRed, "HTTP", "%s 响应写入失败（累计 %d 次）：%v", kind, count, err)
	}
}

func writeHTTPJSON(w http.ResponseWriter, value any) {
	if err := json.NewEncoder(w).Encode(value); err != nil {
		reportHTTPWriteFailure("JSON", err)
	}
}
