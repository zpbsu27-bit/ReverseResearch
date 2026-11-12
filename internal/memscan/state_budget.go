package memscan

const (
	MaxCandidateStateBytes = uint64(64 << 20)
	MaxPersistedScanBytes  = int64(128 << 20)
)

func estimateCandidateStateBytes(candidate Candidate) uint64 {
	const fixed = uint64(128)
	return fixed +
		uint64(len(candidate.AddressHex)) +
		uint64(len(candidate.RawHex)) +
		uint64(len(candidate.Value))
}

func estimateCandidateSliceBytes(candidates []Candidate) uint64 {
	var total uint64
	for _, candidate := range candidates {
		cost := estimateCandidateStateBytes(candidate)
		if !fitsStateBudget(total, cost, ^uint64(0)) {
			return ^uint64(0)
		}
		total += cost
	}
	return total
}

func fitsStateBudget(used, next, limit uint64) bool {
	return next <= limit && used <= limit-next
}
