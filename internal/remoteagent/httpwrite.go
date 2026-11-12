package remoteagent

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync/atomic"
)

var httpWriteFailures atomic.Uint64

// httpWriteFailureLogEvery bounds diagnostic output: a controller that keeps
// dropping connections must not produce one stderr line per failed response
// forever.
const httpWriteFailureLogEvery = 1000

func reportHTTPWriteFailure(kind string, err error) {
	count := httpWriteFailures.Add(1)
	if count == 1 || count%httpWriteFailureLogEvery == 0 {
		log.Printf("remoteagent: write HTTP %s response failed (%d occurrences so far): %v", kind, count, err)
	}
}

func writeHTTPJSON(w http.ResponseWriter, value any) {
	if err := json.NewEncoder(w).Encode(value); err != nil {
		reportHTTPWriteFailure("JSON", err)
	}
}

func writeHTTPString(w http.ResponseWriter, value string) {
	if _, err := io.WriteString(w, value); err != nil {
		reportHTTPWriteFailure("text", err)
	}
}
