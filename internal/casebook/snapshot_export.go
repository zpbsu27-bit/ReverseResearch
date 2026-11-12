package casebook

// Snapshot returns a Case and the SHA-256 revision calculated from the exact
// same durable bytes. It is the public currentness-safe projection boundary
// for report/UI consumers and does not mutate the Case.
func (s *Store) Snapshot(id string) (Case, string, error) {
	return s.snapshot(id)
}
