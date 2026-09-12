export const BUNDLES = [
	"core",
	"dup",
	"security",
	"rust",
	"go",
	"python",
	"js-ts",
	"shell",
	"sql",
	"css",
	"data",
	"api",
	"infra",
	"docs",
] as const;

export type BundleName = (typeof BUNDLES)[number];

export type InstallerKey =
	| "brew"
	| "pipx"
	| "npm"
	| "npm-local"
	| "cargo"
	| "go"
	| "rustup"
	| "manual";

export type ToolRec = {
	readonly name: string;
	readonly bin: string;
	readonly key: InstallerKey;
	readonly hint: string;
	readonly pkg?: string;
	readonly miseSpec?: string;
	readonly probeArgs?: readonly (readonly string[])[];
	/** Optional per-tool probe ceiling; defaults to the global 1.5 second ceiling. */
	readonly probeTimeoutMs?: number;
	readonly runPrefix?: readonly string[];
	readonly hostPackages?: readonly string[];
	readonly hostPackageConfigNames?: Readonly<Record<string, readonly string[]>>;
	readonly configFiles?: readonly string[];
	readonly packageConfigKeys?: readonly string[];
	readonly securityTier?: "project-native" | "lightweight-static" | "deep-static";
};

export type SniffAnalyzerRecipe = {
	readonly id: string;
	readonly tool: string;
	readonly tier: "project-native" | "lightweight-static" | "deep-static";
	readonly args: readonly string[];
	readonly scope: "scoped-files" | "bounded-history" | "repository-wide";
	readonly fileExtensions?: readonly string[];
	readonly targetSeparator?: readonly string[];
	readonly acceptedExitCodes: readonly number[];
	readonly remoteSafe: boolean;
	readonly configFree: boolean;
	readonly projectControlled: boolean;
};


export const OPENGREP_FILE_EXTENSIONS = [
	".bash",
	".c",
	".cc",
	".cfg",
	".conf",
	".cpp",
	".cxx",
	".fish",
	".go",
	".h",
	".hpp",
	".ini",
	".java",
	".js",
	".json",
	".json5",
	".jsonc",
	".jsx",
	".ksh",
	".m",
	".mm",
	".php",
	".proto",
	".ps1",
	".py",
	".rb",
	".rs",
	".sh",
	".sql",
	".swift",
	".tf",
	".toml",
	".ts",
	".tsx",
	".xml",
	".yaml",
	".yml",
	".zsh",
] as const;

export const SNIFF_ANALYZER_RECIPES = {
	"lizard:complexity": {
		id: "lizard:complexity",
		tool: "lizard",
		tier: "lightweight-static",
		args: ["--csv", "-C", "10", "-L", "50", "-a", "5"],
		scope: "scoped-files",
		fileExtensions: [".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".java", ".js", ".jsx", ".m", ".mm", ".php", ".py", ".rb", ".rs", ".swift", ".ts", ".tsx"],
		acceptedExitCodes: [0, 1],
		remoteSafe: true,
		configFree: true,
		projectControlled: false,
	},
	"opengrep:hardcoded-values": {
		id: "opengrep:hardcoded-values",
		tool: "opengrep",
		tier: "lightweight-static",
		args: ["scan", "-f", `${import.meta.dir}/sniff-opengrep-hardcoded-values.yml`, "--json", "--no-rewrite-rule-ids", "--disable-version-check"],
		scope: "scoped-files",
		fileExtensions: OPENGREP_FILE_EXTENSIONS,
		targetSeparator: ["--"],
		acceptedExitCodes: [0],
		remoteSafe: true,
		configFree: true,
		projectControlled: false,
	},
	"gitleaks:tracked-history": {
		id: "gitleaks:tracked-history",
		tool: "gitleaks",
		tier: "lightweight-static",
		args: ["git", "--redact", "--report-format", "json", "--report-path", "-", "--no-banner", "."],
		scope: "repository-wide",
		acceptedExitCodes: [0, 1],
		remoteSafe: false,
		configFree: false,
		projectControlled: false,
	},
} as const satisfies Record<string, SniffAnalyzerRecipe>;

export type SniffAnalyzerRecipeId = keyof typeof SNIFF_ANALYZER_RECIPES;

export const TOOLS = {
	core: [
		{
			name: "opengrep",
			bin: "opengrep",
			key: "manual",
			hint: "sniff_install_tools mode=install bundles=[core]",
			probeArgs: [["--version"]],
			probeTimeoutMs: 60_000,
		},
		{ name: "lizard", bin: "lizard", key: "pipx", hint: "pipx install lizard" },
		{
			name: "scc",
			bin: "scc",
			key: "brew",
			hint: "brew install scc (or: go install github.com/boyter/scc/v4@latest)",
			miseSpec: "go:github.com/boyter/scc/v4",
		},
		{
			name: "ast-grep",
			bin: "sg",
			key: "cargo",
			hint: "cargo install ast-grep --locked",
			pkg: "ast-grep",
		},
		{ name: "tokei", bin: "tokei", key: "cargo", hint: "cargo install tokei" },
	],
	dup: [{ name: "jscpd", bin: "jscpd", key: "npm", hint: "npm i -g jscpd" }],
  security: [
    { name: "trivy", bin: "trivy", key: "brew", hint: "brew install trivy", securityTier: "lightweight-static" },
    {
      name: "checkov",
      bin: "checkov",
      key: "pipx",
      hint: "pipx install checkov",
      securityTier: "lightweight-static",
    },
    {
      name: "gitleaks",
      bin: "gitleaks",
      key: "brew",
      hint: "brew install gitleaks",
      securityTier: "lightweight-static",
    },
  ],
  rust: [
		{
			name: "cargo-clippy",
			bin: "cargo",
			key: "rustup",
			hint: "rustup component add clippy",
			probeTimeoutMs: 10_000,
			probeArgs: [["clippy", "--version"]],
			runPrefix: ["clippy"],
		},
		{
			name: "cargo-machete",
			bin: "cargo-machete",
			key: "cargo",
			hint: "cargo install cargo-machete",
		},
		{
			name: "cargo-udeps",
			bin: "cargo",
			key: "cargo",
			hint: "cargo install cargo-udeps --locked",
			pkg: "cargo-udeps",
			probeArgs: [["+nightly", "udeps", "--version"]],
			probeTimeoutMs: 10_000,
			runPrefix: ["+nightly", "udeps"],
		},
		{
			name: "cargo-geiger",
			bin: "cargo",
			key: "cargo",
			hint: "cargo install cargo-geiger --locked",
			probeTimeoutMs: 10_000,
			pkg: "cargo-geiger",
			probeArgs: [["geiger", "--version"]],
			runPrefix: ["geiger"],
		},
	],
	go: [
		{
			name: "golangci-lint",
			bin: "golangci-lint",
			key: "brew",
			hint: "brew install golangci-lint",
		},
		{
			name: "deadcode",
			bin: "deadcode",
			key: "go",
			hint: "go install golang.org/x/tools/cmd/deadcode@latest",
			miseSpec: "go:golang.org/x/tools/cmd/deadcode",
		},
		{
			name: "go-vet",
			bin: "go",
			key: "manual",
			hint: "install the Go toolchain; sniff does not install language toolchains",
			probeArgs: [["version"]],
			runPrefix: ["vet"],
		},
		{
			name: "staticcheck",
			bin: "staticcheck",
			key: "go",
			hint: "go install honnef.co/go/tools/cmd/staticcheck@latest",
			miseSpec: "go:honnef.co/go/tools/cmd/staticcheck",
		},
		{
			name: "gocyclo",
			bin: "gocyclo",
			key: "go",
			hint: "go install github.com/fzipp/gocyclo/cmd/gocyclo@latest",
			miseSpec: "go:github.com/fzipp/gocyclo/cmd/gocyclo",
		},
		{
			name: "gocognit",
			bin: "gocognit",
			key: "go",
			hint: "go install github.com/uudashr/gocognit/cmd/gocognit@latest",
			miseSpec: "go:github.com/uudashr/gocognit/cmd/gocognit",
		},
		{
			name: "gosec",
			bin: "gosec",
			key: "go",
			hint: "go install github.com/securego/gosec/v2/cmd/gosec@latest",
			miseSpec: "go:github.com/securego/gosec/v2/cmd/gosec",
		},
	],
	python: [
		{ name: "ruff", bin: "ruff", key: "pipx", hint: "pipx install ruff" },
		{
			name: "vulture",
			bin: "vulture",
			key: "pipx",
			hint: "pipx install vulture",
		},
		{ name: "pylint", bin: "pylint", key: "pipx", hint: "pipx install pylint" },
		{ name: "mypy", bin: "mypy", key: "pipx", hint: "pipx install mypy" },
		{
			name: "pyright",
			bin: "pyright",
			key: "pipx",
			hint: "pipx install pyright (or: npm i -g pyright)",
		},
		{ name: "radon", bin: "radon", key: "pipx", hint: "pipx install radon" },
		{ name: "xenon", bin: "xenon", key: "pipx", hint: "pipx install xenon" },
		{ name: "deptry", bin: "deptry", key: "pipx", hint: "pipx install deptry" },
		{ name: "bandit", bin: "bandit", key: "pipx", hint: "pipx install bandit" },
	],
	"js-ts": [
		{
			name: "eslint",
			bin: "eslint",
			key: "npm-local",
			hint: "npm i -D eslint typescript-eslint eslint-plugin-sonarjs eslint-plugin-unicorn",
			hostPackages: [
				"typescript-eslint",
				"eslint-plugin-sonarjs",
				"eslint-plugin-unicorn",
				"eslint-plugin-react",
				"eslint-plugin-react-hooks",
				"eslint-plugin-jsx-a11y",
				"eslint-plugin-vue",
				"eslint-plugin-svelte",
				"@graphql-eslint/eslint-plugin",
			],
			configFiles: [
				"eslint.config.js",
				"eslint.config.mjs",
				"eslint.config.cjs",
				"eslint.config.ts",
				"eslint.config.mts",
				"eslint.config.cts",
				".eslintrc",
				".eslintrc.js",
				".eslintrc.cjs",
				".eslintrc.json",
				".eslintrc.yaml",
				".eslintrc.yml",
			],
			packageConfigKeys: ["eslintConfig"],
			hostPackageConfigNames: {
				"typescript-eslint": ["typescript-eslint"],
				"eslint-plugin-sonarjs": ["sonarjs"],
				"eslint-plugin-unicorn": ["unicorn"],
				"eslint-plugin-react": ["react"],
				"eslint-plugin-react-hooks": ["react-hooks"],
				"eslint-plugin-jsx-a11y": ["jsx-a11y"],
				"eslint-plugin-vue": ["vue"],
				"eslint-plugin-svelte": ["svelte"],
				"@graphql-eslint/eslint-plugin": ["@graphql-eslint"],
			},
		},
		{ name: "tsc", bin: "tsc", key: "npm-local", hint: "npm i -D typescript" },
		{ name: "knip", bin: "knip", key: "npm-local", hint: "npm i -D knip" },
		{
			name: "dependency-cruiser",
			bin: "depcruise",
			key: "npm-local",
			hint: "npm i -D dependency-cruiser",
		},
		{
			name: "type-coverage",
			bin: "type-coverage",
			key: "npm-local",
			hint: "npm i -D type-coverage",
		},
		{ name: "madge", bin: "madge", key: "npm-local", hint: "npm i -D madge" },
		{
			name: "biome",
			bin: "biome",
			key: "npm-local",
			hint: "npm i -D --save-exact @biomejs/biome",
		},
		{
			name: "svelte-check",
			bin: "svelte-check",
			key: "npm-local",
			hint: "npm i -D svelte-check",
		},
		{
			name: "vue-tsc",
			bin: "vue-tsc",
			key: "npm-local",
			hint: "npm i -D vue-tsc",
		},
	],
	shell: [
		{
			name: "shellcheck",
			bin: "shellcheck",
			key: "brew",
			hint: "brew install shellcheck",
		},
		{ name: "shfmt", bin: "shfmt", key: "brew", hint: "brew install shfmt" },
	],
	sql: [
		{
			name: "sqlfluff",
			bin: "sqlfluff",
			key: "pipx",
			hint: "pipx install sqlfluff",
		},
		{
			name: "squawk",
			bin: "squawk",
			key: "cargo",
			hint: "cargo install squawk",
		},
	],
	css: [
		{
			name: "stylelint",
			bin: "stylelint",
			key: "npm-local",
			hint: "npm i -D stylelint stylelint-config-standard stylelint-config-recommended-scss",
			hostPackages: [
				"stylelint-config-standard",
				"stylelint-config-recommended-scss",
				"stylelint-config-recommended-vue",
				"stylelint-declaration-strict-value",
				"stylelint-order",
			],
			configFiles: [
				"stylelint.config.js",
				"stylelint.config.mjs",
				"stylelint.config.cjs",
				"stylelint.config.ts",
				"stylelint.config.mts",
				"stylelint.config.cts",
				".stylelintrc",
				".stylelintrc.js",
				".stylelintrc.cjs",
				".stylelintrc.json",
				".stylelintrc.yaml",
				".stylelintrc.yml",
			],
			packageConfigKeys: ["stylelint"],
			hostPackageConfigNames: {
				"stylelint-config-standard": ["stylelint-config-standard"],
				"stylelint-config-recommended-scss": [
					"stylelint-config-recommended-scss",
				],
				"stylelint-config-recommended-vue": [
					"stylelint-config-recommended-vue",
				],
				"stylelint-declaration-strict-value": [
					"stylelint-declaration-strict-value",
				],
				"stylelint-order": ["stylelint-order"],
			},
		},
		{
			name: "css-analyzer",
			bin: "css-analyzer",
			key: "npm-local",
			hint: "npm i -D @projectwallace/css-analyzer",
			pkg: "@projectwallace/css-analyzer",
		},
	],
	data: [
		{
			name: "yamllint",
			bin: "yamllint",
			key: "pipx",
			hint: "pipx install yamllint",
		},
		{
			name: "taplo",
			bin: "taplo",
			key: "cargo",
			hint: "cargo install taplo-cli --locked",
			pkg: "taplo-cli",
		},
		{
			name: "check-jsonschema",
			bin: "check-jsonschema",
			key: "pipx",
			hint: "pipx install check-jsonschema",
		},
	],
	api: [
		{
			name: "vacuum",
			bin: "vacuum",
			key: "brew",
			hint: "brew install daveshanley/vacuum/vacuum",
			pkg: "daveshanley/vacuum/vacuum",
		},
		{
			name: "spectral",
			bin: "spectral",
			key: "npm",
			hint: "npm i -g @stoplight/spectral-cli",
			pkg: "@stoplight/spectral-cli",
		},
		{
			name: "openapi-spec-validator",
			bin: "openapi-spec-validator",
			key: "pipx",
			hint: "pipx install openapi-spec-validator",
		},
		{
			name: "oasdiff",
			bin: "oasdiff",
			key: "brew",
			hint: "brew install oasdiff/homebrew-oasdiff/oasdiff",
			pkg: "oasdiff/homebrew-oasdiff/oasdiff",
		},
		{
			name: "graphql-inspector",
			bin: "graphql-inspector",
			key: "npm",
			hint: "npm i -g @graphql-inspector/cli",
			pkg: "@graphql-inspector/cli",
		},
		{
			name: "buf",
			bin: "buf",
			key: "brew",
			hint: "brew install bufbuild/buf/buf",
			pkg: "bufbuild/buf/buf",
		},
		{
			name: "protolint",
			bin: "protolint",
			key: "go",
			hint: "go install github.com/yoheimuta/protolint/cmd/protolint@latest",
			miseSpec: "go:github.com/yoheimuta/protolint/cmd/protolint",
		},
	],
	infra: [
		{
			name: "hadolint",
			bin: "hadolint",
			key: "brew",
			hint: "brew install hadolint",
		},
		{ name: "tflint", bin: "tflint", key: "brew", hint: "brew install tflint" },
		{
			name: "terraform",
			bin: "terraform",
			key: "brew",
			hint: "brew install terraform",
		},
		{
			name: "actionlint",
			bin: "actionlint",
			key: "brew",
			hint: "brew install actionlint",
		},
		{ name: "zizmor", bin: "zizmor", key: "pipx", hint: "pipx install zizmor" },
		{
			name: "pinact",
			bin: "pinact",
			key: "go",
			hint: "go install github.com/suzuki-shunsuke/pinact/cmd/pinact@latest",
			miseSpec: "go:github.com/suzuki-shunsuke/pinact/cmd/pinact",
		},
		{
			name: "glab-ci-lint",
			bin: "glab",
			key: "brew",
			hint: "brew install glab",
			probeArgs: [["ci", "lint", "--help"]],
			runPrefix: ["ci", "lint"],
		},
		{
			name: "kube-linter",
			bin: "kube-linter",
			key: "brew",
			hint: "brew install kube-linter",
		},
		{
			name: "kubeconform",
			bin: "kubeconform",
			key: "brew",
			hint: "brew install kubeconform",
		},
	],
	docs: [
		{
			name: "markdownlint-cli2",
			bin: "markdownlint-cli2",
			key: "npm",
			hint: "npm i -g markdownlint-cli2",
		},
		{
			name: "lychee",
			bin: "lychee",
			key: "cargo",
			hint: "cargo install lychee",
		},
		{ name: "cspell", bin: "cspell", key: "npm", hint: "npm i -g cspell" },
	],
} as const satisfies Record<BundleName, readonly ToolRec[]>;
