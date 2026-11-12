package pointermap

const (
	MaxChainStateBytes    = uint64(64 << 20)
	MaxFrontierStateBytes = uint64(64 << 20)
	MaxPersistedMapBytes  = int64(128 << 20)
)

func estimateChainStateBytes(chain Chain) uint64 {
	const fixed = uint64(192)
	return fixed +
		uint64(len(chain.SourceRootHex)) +
		uint64(len(chain.Anchor.ModulePath)) +
		uint64(len(chain.Anchor.ModuleSHA256)) +
		uint64(len(chain.Offsets))*8 +
		uint64(len(chain.SourceSlots))*8
}

func estimateChainSliceBytes(chains []Chain) uint64 {
	var total uint64
	for _, chain := range chains {
		cost := estimateChainStateBytes(chain)
		if !fitsPointerStateBudget(total, cost, ^uint64(0)) {
			return ^uint64(0)
		}
		total += cost
	}
	return total
}

func estimateSearchChainStateBytes(chain searchChain) uint64 {
	const fixed = uint64(64)
	return fixed + uint64(len(chain.Offsets))*8 + uint64(len(chain.Slots))*8
}

func fitsPointerStateBudget(used, next, limit uint64) bool {
	return next <= limit && used <= limit-next
}
