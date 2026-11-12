package job

const (
	MaxJobRecordBytes = 1 << 20
	MaxJobShardFiles  = 256
	MaxJobShardBytes  = int64(8 << 20)
)
