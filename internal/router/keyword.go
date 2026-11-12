package router

import "strings"

// keywordMatches keeps CJK substring matching while preventing ASCII keywords
// such as "cti" from matching inside "function". Inputs are already normalized
// by Route. Punctuation and CJK neighbors separate ASCII words.
func keywordMatches(text, keyword string) bool {
	if keyword == "" {
		return false
	}
	for offset := 0; offset <= len(text)-len(keyword); {
		index := strings.Index(text[offset:], keyword)
		if index < 0 {
			return false
		}
		start := offset + index
		end := start + len(keyword)
		left := !asciiWord(keyword[0]) || start == 0 || !asciiWord(text[start-1])
		right := !asciiWord(keyword[len(keyword)-1]) || end == len(text) || !asciiWord(text[end])
		if left && right {
			return true
		}
		offset = start + 1
	}
	return false
}

func asciiWord(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}
