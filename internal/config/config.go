package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server        ServerConfig        `yaml:"server"`
	Transport     TransportConfig     `yaml:"transport"`
	Web           WebConfig           `yaml:"web"`
	OAuth         OAuthConfig         `yaml:"oauth"`
	Teleport      TeleportConfig      `yaml:"teleport"`
	Redis         RedisConfig         `yaml:"redis"`
	S3            S3Config            `yaml:"s3"`
	Embedding     ModelConfig         `yaml:"embedding"`
	Summarization ModelConfig         `yaml:"summarization"`
	VectorBackend VectorBackendConfig `yaml:"vector_backend"`
	Metadata      MetadataConfig      `yaml:"metadata_catalog"`
	Chunking      ChunkingConfig      `yaml:"chunking"`
	Limits        LimitsConfig        `yaml:"limits"`
	API           APIConfig           `yaml:"api"`
	Search        SearchConfig        `yaml:"search"`
	Usage         UsageConfig         `yaml:"usage"`
}

type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

type TransportConfig struct {
	StreamableHTTP bool `yaml:"streamable_http"`
	LegacySSE      bool `yaml:"legacy_sse"`
}

type WebConfig struct {
	EnableUI bool             `yaml:"enable_ui"`
	Admin    DefaultAdminConfig `yaml:"default_admin"`
}

type DefaultAdminConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Username      string `yaml:"username"`
	PasswordEnvRef string `yaml:"password_env_ref"`
	SessionTTLHours int  `yaml:"session_ttl_hours"`
}

type OAuthConfig struct {
	Providers     []ProviderConfig `yaml:"providers"`
	GoogleDomains []string         `yaml:"google_allowed_domains"`
}

type ProviderConfig struct {
	Name     string `yaml:"name"`
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
	JWKSURL  string `yaml:"jwks_url"`
}

type TeleportConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
}

type RedisConfig struct {
	Addr      string `yaml:"addr"`
	Password  string `yaml:"password"`
	DB        int    `yaml:"db"`
	KeyPrefix string `yaml:"key_prefix"`
	TTLHours  int    `yaml:"ttl_hours"`
}

type S3Config struct {
	Endpoint        string `yaml:"endpoint"`
	Bucket          string `yaml:"bucket"`
	LargeDocBytes   int64  `yaml:"large_document_threshold_bytes"`
	AccessKeyEnvRef string `yaml:"access_key_env_ref"`
	SecretKeyEnvRef string `yaml:"secret_key_env_ref"`
	UseSSL          bool   `yaml:"use_ssl"`
}

type ModelConfig struct {
	Provider        string `yaml:"provider"`
	Model           string `yaml:"model"`
	API             string `yaml:"api"`
	APIKeyEnvRef    string `yaml:"api_key_env_ref"`
	MaxInputTokens  int    `yaml:"max_input_tokens"`
	MaxOutputTokens int    `yaml:"max_output_tokens"`
}

type VectorBackendConfig struct {
	Active           string `yaml:"active"`
	QdrantURL        string `yaml:"qdrant_url"`
	QdrantCollection string `yaml:"qdrant_collection"`
}

type MetadataConfig struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

type ChunkingConfig struct {
	ChunkSize int `yaml:"chunk_size"`
	Overlap   int `yaml:"overlap"`
}

type LimitsConfig struct {
	MaxUploadBytes int64 `yaml:"max_upload_bytes"`
}

type APIConfig struct {
	Scopes           []string `yaml:"scopes"`
	AllowedOrigins   []string `yaml:"allowed_origins"`
	TrustedProxyCIDR []string `yaml:"trusted_proxy_cidrs"`
}

type UsageConfig struct {
	Enabled          bool                  `yaml:"enabled"`
	RedisTimeSeries  bool                  `yaml:"redis_timeseries"`
	RetentionHours   int                   `yaml:"retention_hours"`
	DefaultRateLimit RateLimitConfig       `yaml:"default_rate_limit"`
	Exporters        UsageExportersConfig  `yaml:"exporters"`
}

type RateLimitConfig struct {
	RequestsPerMinute int `yaml:"requests_per_minute"`
	RequestsPerHour   int `yaml:"requests_per_hour"`
	RequestsPerDay    int `yaml:"requests_per_day"`
	Burst              int `yaml:"burst"`
}

type UsageExportersConfig struct {
	Prometheus      PrometheusExporterConfig      `yaml:"prometheus"`
	VictoriaMetrics VictoriaMetricsExporterConfig `yaml:"victoriametrics"`
}

type PrometheusExporterConfig struct {
	Enabled bool `yaml:"enabled"`
}

type VictoriaMetricsExporterConfig struct {
	Enabled         bool   `yaml:"enabled"`
	RemoteWriteURL  string `yaml:"remote_write_url"`
	IntervalSeconds int    `yaml:"interval_seconds"`
}

func (c Config) AccessKey() string {
	return resolveSecret(c.S3.AccessKeyEnvRef)
}

func (c Config) SecretKey() string {
	return resolveSecret(c.S3.SecretKeyEnvRef)
}

func (c Config) EmbeddingAPIKey() string {
	return resolveSecret(c.Embedding.APIKeyEnvRef)
}

func (c Config) SummarizationAPIKey() string {
	return resolveSecret(c.Summarization.APIKeyEnvRef)
}

func (c Config) DefaultAdminPassword() string {
	return resolveSecret(c.Web.Admin.PasswordEnvRef)
}

type SearchConfig struct {
	Filters SearchFilterConfig `yaml:"filters"`
}

type SearchFilterConfig struct {
	SourceURL SourceURLFilterConfig `yaml:"source_url"`
}

type SourceURLFilterConfig struct {
	AllowPartialMatch bool `yaml:"allow_partial_match"`
}

func Load(path string) (Config, error) {
	loadDotEnvCandidates(path)

	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.Server.ListenAddr == "" {
		return errors.New("server.listen_addr is required")
	}
	if c.Chunking.ChunkSize <= 0 {
		return errors.New("chunking.chunk_size must be > 0")
	}
	if c.Summarization.Model == "" {
		return errors.New("summarization.model is required")
	}
	if c.Embedding.Model == "" {
		return errors.New("embedding.model is required")
	}
	if c.Redis.TTLHours <= 0 {
		c.Redis.TTLHours = 24
	}
	if c.Redis.KeyPrefix == "" {
		c.Redis.KeyPrefix = "syna"
	}
	if c.Web.Admin.Username == "" {
		c.Web.Admin.Username = "admin"
	}
	if c.Web.Admin.SessionTTLHours <= 0 {
		c.Web.Admin.SessionTTLHours = 12
	}
	if c.Usage.RetentionHours <= 0 {
		c.Usage.RetentionHours = 720
	}
	if c.Usage.DefaultRateLimit.RequestsPerMinute <= 0 {
		c.Usage.DefaultRateLimit.RequestsPerMinute = 60
	}
	if c.Usage.DefaultRateLimit.RequestsPerHour <= 0 {
		c.Usage.DefaultRateLimit.RequestsPerHour = 1000
	}
	if c.Usage.DefaultRateLimit.RequestsPerDay <= 0 {
		c.Usage.DefaultRateLimit.RequestsPerDay = 10000
	}
	if c.Usage.DefaultRateLimit.Burst <= 0 {
		c.Usage.DefaultRateLimit.Burst = 20
	}
	if c.Usage.Exporters.VictoriaMetrics.IntervalSeconds <= 0 {
		c.Usage.Exporters.VictoriaMetrics.IntervalSeconds = 30
	}
	if c.Metadata.DSN == "" {
		return errors.New("metadata_catalog.dsn is required")
	}
	if len(c.API.AllowedOrigins) == 0 {
		return errors.New("api.allowed_origins must not be empty")
	}
	for _, p := range c.OAuth.Providers {
		if p.Issuer == "" || p.Audience == "" {
			return fmt.Errorf("oauth provider %q missing issuer/audience", p.Name)
		}
	}
	return nil
}

func resolveSecret(value string) string {
	if strings.HasPrefix(value, "env:") {
		return os.Getenv(strings.TrimPrefix(value, "env:"))
	}
	if strings.HasPrefix(value, "$") {
		return os.Getenv(strings.TrimPrefix(value, "$"))
	}
	if strings.HasPrefix(value, "literal:") {
		return strings.TrimPrefix(value, "literal:")
	}
	return value
}

func loadDotEnvCandidates(configPath string) {
	candidates := []string{".env"}
	if configPath != "" {
		configDir := filepath.Dir(configPath)
		candidates = append(candidates,
			filepath.Join(configDir, ".env"),
			filepath.Join(configDir, "..", ".env"),
		)
	}
	for _, candidate := range candidates {
		loadDotEnv(candidate)
	}
}

func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		if key == "" || os.Getenv(key) != "" {
			continue
		}
		_ = os.Setenv(key, value)
	}
}
