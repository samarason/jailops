package api

// Project splits a host into workloads that cannot see or disturb each other.
// A project owns jails, volumes, firewall policies, address sets, snapshots
// and backup policies, and uses networks and images granted to it. Projects
// are ScopeHost objects.
type Project struct {
	Metadata ObjectMeta    `json:"metadata"`
	Spec     ProjectSpec   `json:"spec"`
	Status   ProjectStatus `json:"status"`
}

// ProjectSpec is the desired state of a project.
type ProjectSpec struct {
	// Comment is what the project is for.
	Comment string `json:"comment,omitempty"`
	// Hosts lists the hosts a fleet project spans. Empty means this host
	// only. The definition is fleet-level; each host implements the named
	// networks and storage locally and enforces its own copy.
	Hosts []string `json:"hosts,omitempty"`
	// Networks are the networks the project may attach jails to.
	Networks []ProjectNetwork `json:"networks,omitempty"`
	// Storage lists the storage the project may place jails and volumes on.
	Storage []ProjectStorage `json:"storage,omitempty"`
	Quotas  ProjectQuotas    `json:"quotas,omitempty"`
	// FirewallPolicies are the project's mandatory policies, rendered in this order before a jail's own.
	FirewallPolicies []string `json:"firewall_policies,omitempty"`
	// Images is an allow-list of image names; empty allows every image.
	Images []string `json:"images,omitempty"`
	// NewNetwork is a create-time convenience: the server creates a dedicated
	// network with a subnet from its configured pool of subnets, grants it to the
	// project and clears this flag. It is never stored as true.
	NewNetwork bool `json:"new_network,omitempty"`
}

// SoleNetwork is the network a jail of the project is attached to when it names none: the project's only network
// grant, or "" when the project has none or several.
func (s ProjectSpec) SoleNetwork() string {
	if len(s.Networks) == 1 {
		return s.Networks[0].Network
	}
	return ""
}

// SoleStorage is the storage a jail of the project is placed on when it names none: the project's only storage
// grant, or "" when the project has none, several, or the grant of every storage ("*").
func (s ProjectSpec) SoleStorage() string {
	if len(s.Storage) == 1 && s.Storage[0].Storage != "*" {
		return s.Storage[0].Storage
	}
	return ""
}

// ProjectNetwork grants a network to a project. A network belongs to at most
// one project: it is used whole by the project it is granted to, and is never
// shared.
type ProjectNetwork struct {
	// Network is a network name.
	Network string `json:"network"`
}

// ProjectStorage grants storage to a project.
type ProjectStorage struct {
	// Storage is a storage name, or "*" for every storage of the host. There is no default storage: a jail
	// names the storage it is placed on, or a profile does.
	Storage string `json:"storage"`
	// Quota bounds the project's dataset on this storage ("500G"); empty is
	// unlimited.
	Quota string `json:"quota,omitempty"`
}

// ProjectQuotas bound a project. Zero means unlimited.
type ProjectQuotas struct {
	Jails     int    `json:"jails,omitempty"`
	CPU       int    `json:"cpu,omitempty"`
	Memory    string `json:"memory,omitempty"`
	PIDs      int    `json:"pids,omitempty"`
	Addresses int    `json:"addresses,omitempty"`
}

// ProjectStatus reports usage against the quotas.
type ProjectStatus struct {
	Jails      int         `json:"jails"`
	CPU        int         `json:"cpu"`
	MemoryUsed int64       `json:"memory_used"`
	DiskUsed   int64       `json:"disk_used"`
	Addresses  int         `json:"addresses"`
	Conditions []Condition `json:"conditions,omitempty"`
}

// Storage is a named ZFS location on a host. Jail and volume datasets are
// created under it. Storage is a host-managed resource; projects are granted
// access to it. Storage is a ScopeHost object.
type Storage struct {
	Metadata ObjectMeta    `json:"metadata"`
	Spec     StorageSpec   `json:"spec"`
	Status   StorageStatus `json:"status"`
}

// StorageSpec is the desired state of a storage location.
type StorageSpec struct {
	// Dataset is the ZFS dataset that holds jailops data, for example
	// "tank/jailops". It must exist and live on an imported pool.
	Dataset string `json:"dataset"`
	// Comment is what the storage is for.
	Comment string `json:"comment,omitempty"`
	// Compression, when set, is applied to new datasets ("zstd", "lz4").
	Compression string `json:"compression,omitempty"`
	// Encrypted is reserved: native ZFS encryption is not implemented and creating a storage with it set is refused.
	Encrypted bool `json:"encrypted,omitempty"`
}

// StorageStatus is the observed state of a storage location.
type StorageStatus struct {
	Pool          string      `json:"pool,omitempty"`
	Health        string      `json:"health,omitempty"`
	Size          int64       `json:"size,omitempty"`
	Used          int64       `json:"used,omitempty"`
	Available     int64       `json:"available,omitempty"`
	Fragmentation int         `json:"fragmentation,omitempty"`
	Conditions    []Condition `json:"conditions,omitempty"`
}

// ProjectHostStatus is one host's view of a fleet project.
type ProjectHostStatus struct {
	// Host is the host as listed in spec.hosts.
	Host     string `json:"host"`
	HostUUID string `json:"host_uuid,omitempty"`
	Online   bool   `json:"online"`
	// Applied is true when the host holds this project; InSync when its copy
	// equals the definition held by the hub.
	Applied    bool  `json:"applied"`
	InSync     bool  `json:"in_sync"`
	Generation int64 `json:"generation,omitempty"`
	// Status is the usage the host reports.
	Status *ProjectStatus `json:"status,omitempty"`
	// Error says why the host could not be read or written.
	Error      *Error      `json:"error,omitempty"`
	Conditions []Condition `json:"conditions,omitempty"`
}

// ProjectAggregate is the reply of GET /api/v1/projects/<name>?host=all on a
// hub: the definition and the state on every host the project lists.
type ProjectAggregate struct {
	Project Project             `json:"project"`
	Hosts   []ProjectHostStatus `json:"hosts"`
	// Total sums the usage of the hosts that answered.
	Total ProjectStatus `json:"total"`
}
