package api

// AppCategory is the fixed list a catalog entry files itself under.
type AppCategory string

// App categories.
const (
	AppDatabase      AppCategory = "database"
	AppWeb           AppCategory = "web"
	AppTools         AppCategory = "tools"
	AppDevops        AppCategory = "devops"
	AppStorage       AppCategory = "storage"
	AppMonitoring    AppCategory = "monitoring"
	AppCommunication AppCategory = "communication"
	AppNetwork       AppCategory = "network"
	AppSecurity      AppCategory = "security"
	AppOther         AppCategory = "other"
)

// AppCategories lists every category, in the order the console shows them.
var AppCategories = []AppCategory{AppDatabase, AppWeb, AppTools, AppDevops, AppStorage, AppMonitoring, AppCommunication, AppNetwork, AppSecurity, AppOther}

// App is one definition of the application catalog (docs/apps.md): a jail
// that runs one or more packages, with what an operator needs to know to run
// it. The YAML keys are the JSON keys. The daemon reads the definitions from
// local files only; nothing is fetched.
type App struct {
	// Version is the format version; 1.
	Version int `json:"version" yaml:"version"`
	// Name is the catalog name (a jail name) and the file name without .yaml.
	Name  string `json:"name" yaml:"name"`
	Title string `json:"title" yaml:"title"`
	// Summary is one line of at most 140 characters.
	Summary string `json:"summary" yaml:"summary"`
	// Description is plain text paragraphs, at most 2000 characters.
	Description string      `json:"description,omitempty" yaml:"description"`
	Category    AppCategory `json:"category" yaml:"category"`
	// Homepage is an https URL.
	Homepage string `json:"homepage,omitempty" yaml:"homepage"`
	License  string `json:"license,omitempty" yaml:"license"`
	// Icon is the file name of a png or svg next to the definition.
	Icon     string       `json:"icon,omitempty" yaml:"icon"`
	Image    AppImage     `json:"image" yaml:"image"`
	Packages []AppPackage `json:"packages" yaml:"packages"`
	Services []AppService `json:"services,omitempty" yaml:"services"`
	Ports    []AppPort    `json:"ports,omitempty" yaml:"ports"`
	// Data lists the paths that hold the application's state; each becomes
	// a persistent dataset of the jail.
	Data   []AppPath   `json:"data,omitempty" yaml:"data"`
	Config []AppConfig `json:"config,omitempty" yaml:"config"`
	Logs   []AppLog    `json:"logs,omitempty" yaml:"logs"`
	// Setup is run once in the jail after the packages are installed and
	// rc.conf is written, before the services start: argv, never a shell.
	Setup [][]string `json:"setup,omitempty" yaml:"setup"`
	// SysVIPC asks for System V IPC in the jail (JailSpec.SysVIPC): the server needs
	// shared memory, semaphores or message queues, which a jail has none of by default.
	SysVIPC bool `json:"sysvipc,omitempty" yaml:"sysvipc"`
	// StopTimeout is the shutdown budget the app recommends, in seconds: a database that needs a minute to close says
	// 60. It becomes boot.stop_timeout of the jail (1 to MaxStopTimeout); empty leaves the default of JailOps.
	StopTimeout int        `json:"stop_timeout,omitempty" yaml:"stop_timeout"`
	Health      *AppHealth `json:"health,omitempty" yaml:"health"`
	// Resources are hints for the jail's limits, not limits.
	Resources AppResources `json:"resources,omitempty" yaml:"resources"`
	// Notes is shown after the installation.
	Notes string `json:"notes,omitempty" yaml:"notes"`
	// Access is optional: what an allow does inside the jail besides the
	// firewall rule (docs/apps.md, "Who may connect"). A daemon older than
	// the key lists a definition that has it as invalid.
	Access *AppAccessDef `json:"access,omitempty" yaml:"access"`
}

// AppImage says what the jail is built from.
type AppImage struct {
	// OS is "freebsd".
	OS string `json:"os" yaml:"os"`
	// ReleaseMin is the oldest release the application was written for, "15.1" or later.
	ReleaseMin string `json:"release_min" yaml:"release_min"`
}

// AppPackage is one package to install.
type AppPackage struct {
	Name string `json:"name" yaml:"name"`
	// Repo is "ports" (the FreeBSD repository, the default) or "jailops".
	Repo string `json:"repo" yaml:"repo"`
	// Version is the version the definition was written against; informational,
	// pkg installs what the repository has.
	Version string `json:"version,omitempty" yaml:"version"`
}

// AppService is one rc.d service of the application.
type AppService struct {
	// Name is the rc.d script name.
	Name string `json:"name" yaml:"name"`
	// RC are rc.conf knobs besides <name>_enable, which the installer writes.
	RC map[string]string `json:"rc,omitempty" yaml:"rc"`
	// Start says whether the service is started after the installation (default true).
	Start *bool `json:"start,omitempty" yaml:"start"`
}

// AppPort is a port the application listens on.
type AppPort struct {
	Name string `json:"name" yaml:"name"`
	Port int    `json:"port" yaml:"port"`
	// Proto is tcp (the default) or udp.
	Proto       string `json:"proto" yaml:"proto"`
	Description string `json:"description,omitempty" yaml:"description"`
	// Expose says whether the installer forwards the port by default.
	Expose bool `json:"expose" yaml:"expose"`
}

// AppPath is a data path of the application.
type AppPath struct {
	Path        string `json:"path" yaml:"path"`
	Description string `json:"description,omitempty" yaml:"description"`
}

// AppConfig is a configuration file of the application.
type AppConfig struct {
	Path        string `json:"path" yaml:"path"`
	Description string `json:"description,omitempty" yaml:"description"`
	// Restart names the service to restart after a change; empty when none.
	Restart string `json:"restart,omitempty" yaml:"restart"`
}

// AppLog is a log file or directory of the application.
type AppLog struct {
	Name        string `json:"name" yaml:"name"`
	Path        string `json:"path" yaml:"path"`
	Description string `json:"description,omitempty" yaml:"description"`
}

// AppHealth is the check the installer runs after the services started:
// exactly one of TCP, HTTP and Exec.
type AppHealth struct {
	// TCP is a port a connection must succeed to.
	TCP int `json:"tcp,omitempty" yaml:"tcp"`
	// HTTP is a request that must answer with Status.
	HTTP *AppHTTPCheck `json:"http,omitempty" yaml:"http"`
	// Exec is a command run in the jail that must exit 0.
	Exec []string `json:"exec,omitempty" yaml:"exec"`
	// WaitSeconds is how long the check may take to pass (at most 300; default 60).
	WaitSeconds int `json:"wait_seconds,omitempty" yaml:"wait_seconds"`
}

// AppHTTPCheck is an HTTP health check.
type AppHTTPCheck struct {
	Port int    `json:"port" yaml:"port"`
	Path string `json:"path" yaml:"path"`
	// Status is the expected status code (default 200).
	Status int `json:"status,omitempty" yaml:"status"`
}

// AppResources are size hints: memory and disk as sizes ("512M"), cpu as a count.
type AppResources struct {
	Memory string `json:"memory,omitempty" yaml:"memory"`
	Disk   string `json:"disk,omitempty" yaml:"disk"`
	CPU    string `json:"cpu,omitempty" yaml:"cpu"`
}

// AppSource says which directory of the host a definition was read from.
type AppSource string

// Sources of a definition.
const (
	// AppSourceCatalog is the packaged catalog (apps.catalog_dir, installed by jailops-apps).
	AppSourceCatalog AppSource = "catalog"
	// AppSourceLocal is the host's own directory (apps.local_dir), for definitions an
	// operator writes; a local definition wins over a packaged one of the same name.
	AppSourceLocal AppSource = "local"
)

// AppSummary is one row of GET /api/v1/apps. An invalid definition is listed
// with Valid false and the reason, under the name of its file.
type AppSummary struct {
	Name     string      `json:"name"`
	Title    string      `json:"title,omitempty"`
	Summary  string      `json:"summary,omitempty"`
	Category AppCategory `json:"category,omitempty"`
	// Version is the version of the first package when the definition states one.
	Version string `json:"version,omitempty"`
	Valid   bool   `json:"valid"`
	// Error says why the definition is invalid.
	Error string `json:"error,omitempty"`
	// Source is where the definition was read from: catalog or local.
	Source AppSource `json:"source"`
	// Overrides is "catalog" when a local definition hides the packaged one of the same name.
	Overrides AppSource `json:"overrides,omitempty"`
}

// AppDetail is GET /api/v1/apps/<name>: the definition, the hash of its file
// and its icon.
type AppDetail struct {
	Definition App `json:"definition"`
	// Hash is "sha256:<hex>" of the definition file.
	Hash string `json:"hash"`
	// File is the name of the definition file in the catalog directory.
	File string `json:"file"`
	// Icon is the icon as a data URI (image/png or image/svg+xml); empty without one.
	Icon string `json:"icon,omitempty"`
	// Source is where the definition was read from: catalog or local.
	Source AppSource `json:"source"`
	// Overrides is "catalog" when a local definition hides the packaged one of the same name.
	Overrides AppSource `json:"overrides,omitempty"`
}

// Labels the installer puts on the jail of an app.
const (
	// LabelApp is the name of the installed app.
	LabelApp = "jailops.app"
	// LabelAppHash is the hash of the definition file at the installation.
	LabelAppHash = "jailops.app.hash"
	// LabelAppVersion is the version of the first package as it was installed.
	LabelAppVersion = "jailops.app.version"
)

// AppInstall is the body of POST /api/v1/apps/<name>/install. The jail is
// created in the project of the request, like every other jail.
type AppInstall struct {
	// Jail is the name of the jail to create (default: the app name).
	Jail string `json:"jail,omitempty"`
	// Project, when set, must be the project of the request.
	Project string `json:"project,omitempty"`
	// Network and Storage are what the jail is created with; when the project
	// is granted exactly one of a kind it is the default.
	Network string `json:"network,omitempty"`
	Storage string `json:"storage,omitempty"`
	// Image is the image reference (default: the FreeBSD image of the highest
	// release the host runs, by its bare name); its release must be at least
	// the definition's release_min.
	Image string `json:"image,omitempty"`
	// Limits replaces the definition's resource hints as the jail's limits.
	Limits *Resources `json:"limits,omitempty"`
	// DryRun returns the steps of the installation and changes nothing.
	DryRun bool `json:"dry_run,omitempty"`
}

// AppInstalledPort is one port of an installed app with where it listens.
type AppInstalledPort struct {
	Name  string `json:"name"`
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	// Endpoint is "<first address of the jail>:<port>".
	Endpoint string `json:"endpoint,omitempty"`
	// Expose says whether the definition asks for the port to be forwarded; the
	// installer records it and forwards nothing yet. Every port is closed until
	// a source is allowed (POST /api/v1/jails/<name>/access).
	Expose      bool   `json:"expose"`
	Description string `json:"description,omitempty"`
}

// AppInstallResult is the result of the install operation: the jail, how to
// reach the app, where its data, configuration and logs are, and the notes of
// the definition. A dry run carries the steps only.
type AppInstallResult struct {
	App  string `json:"app"`
	Hash string `json:"hash"`
	// Version is the installed version of the first package.
	Version   string             `json:"version,omitempty"`
	Jail      Jail               `json:"jail"`
	Addresses []string           `json:"addresses,omitempty"`
	Ports     []AppInstalledPort `json:"ports,omitempty"`
	Data      []AppPath          `json:"data,omitempty"`
	Config    []AppConfig        `json:"config,omitempty"`
	Logs      []AppLog           `json:"logs,omitempty"`
	Notes     string             `json:"notes,omitempty"`
	// Snapshot is the snapshot taken of the fresh installation ("app-installed").
	Snapshot string `json:"snapshot,omitempty"`
	// Steps describes the plan: every step of the installation, in order.
	Steps  []string `json:"steps"`
	DryRun bool     `json:"dry_run,omitempty"`
}

// AppDraft is GET /api/v1/jails/<name>/app-draft: a definition drafted from a
// running jail, for a person to complete and send to the catalog. It holds
// what the jail shows (the packages installed on purpose, the services enabled
// in rc.conf and their knobs, the listening sockets, the volumes, the names of
// configuration files and logs written since the packages were installed, the
// owners of those directories) and TODO markers for what it cannot know. It
// never holds the content of a configuration file.
type AppDraft struct {
	// Jail is the jail the draft was made from.
	Jail       string `json:"jail"`
	Definition App    `json:"definition"`
	// Todo maps a top-level key of the definition to what is left to do there.
	Todo map[string]string `json:"todo,omitempty"`
	// Findings say what was found and what was left out, one line each.
	Findings []string `json:"findings"`
}
