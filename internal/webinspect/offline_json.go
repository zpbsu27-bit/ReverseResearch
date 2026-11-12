package webinspect

import "reverseresearch/internal/recordio"

func decodeOfflineJSON(body []byte, out any) error { return recordio.DecodeJSON(body, out) }
func checkExpectedSHA256(actual, expected string) error {
	return recordio.CheckExpectedSHA256(actual, expected)
}
