package api

// CommentText returns the comment of a specification (see Commented).
func (s JailSpec) CommentText() string         { return s.Comment }
func (s NetworkSpec) CommentText() string      { return s.Comment }
func (s ImageSpec) CommentText() string        { return s.Comment }
func (s CertificateSpec) CommentText() string  { return s.Comment }
func (s UserSpec) CommentText() string         { return s.Comment }
func (s RemoteSpec) CommentText() string       { return s.Comment }
func (s TokenSpec) CommentText() string        { return s.Comment }
func (s BackupTargetSpec) CommentText() string { return s.Comment }
func (s BackupPolicySpec) CommentText() string { return s.Comment }
func (s WireGuardSpec) CommentText() string    { return s.Comment }
func (s ProfileSpec) CommentText() string      { return s.Comment }
func (s ProjectSpec) CommentText() string      { return s.Comment }
func (s StorageSpec) CommentText() string      { return s.Comment }
