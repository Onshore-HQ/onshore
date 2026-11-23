// Command rv is the installer and operator tool for self-hosted Onshore.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"onshore/data-plane/ee/logproc"
	"onshore/data-plane/internal/audit"
	"onshore/data-plane/internal/detect"
	"onshore/data-plane/internal/license"
	"onshore/data-plane/internal/mask"
	"onshore/data-plane/internal/store"
	"onshore/data-plane/internal/tlsutil"
	"onshore/data-plane/migrations"
)

const usage = `rv: Onshore operator tool

  rv init [-dir .] [-license file]   write .env with generated secrets
  rv migrate                         apply database migrations (DATABASE_URL)
  rv keys init                       initialise OpenBao: 5 shares, threshold 3
  rv keys unseal                     enter unseal shares (needs any 3)
  rv keys status                     show seal state
  rv tls renew [-dir .]              new internal CA and certificates for every service
  rv doctor [-env .env]              pass/fail report for your change ticket
  rv scan <file|->                   shadow-mode leak report, changes nothing
  rv sa-keygen                       make a service-account key pair
  rv license keygen|sign|verify      vendor licence tooling
  rv bundle sign|verify              sign a release's checksums; verify before install
  rv support-bundle                  versions, config without secrets, redacted logs
  rv import -help                    load a CSV of existing data into a vault, and write tokens
  rv token -help                     print a 15-minute bearer token for a service account, for trying the API
  rv admin-recover -email <address>  a one-time link for a locked-out admin (DATABASE_URL)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	var err error
	args := os.Args[2:]
	switch os.Args[1] {
	case "init":
		err = cmdInit(args)
	case "migrate":
		err = cmdMigrate()
	case "keys":
		err = cmdKeys(args)
	case "doctor":
		err = cmdDoctor(args)
	case "scan":
		err = cmdScan(args)
	case "sa-keygen":
		err = cmdSAKeygen()
	case "license":
		err = cmdLicense(args)
	case "bundle":
		err = cmdBundle(args)
	case "support-bundle":
		err = cmdSupportBundle()
	case "admin-recover":
		err = cmdAdminRecover(args)
	case "import":
		err = cmdImport(args)
	case "token":
		err = cmdToken(args)
	case "tls":
		err = cmdTLS(args)
	default:
		fmt.Print(usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func secret(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// installCountry reads the install's country from the flag, or asks for it. A
// vault's country is final, so an empty or malformed answer is refused, not guessed.
func installCountry(flagValue string, in io.Reader, out io.Writer) (string, error) {
	v := flagValue
	if v == "" {
		fmt.Fprint(out, "Which country will this install keep data in? Two-letter code, e.g. US, GB, DE, AE: ")
		line, _ := bufio.NewReader(in).ReadString('\n')
		v = line
	}
	v = strings.ToUpper(strings.TrimSpace(v))
	if len(v) != 2 || v[0] < 'A' || v[0] > 'Z' || v[1] < 'A' || v[1] > 'Z' {
		return "", fmt.Errorf("country must be a two-letter code such as NG, GB or AE; got %q", v)
	}
	return v, nil
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", ".", "directory to write .env in")
	lic := fs.String("license", "", "licence file to install")
	host := fs.String("host", "localhost", "DNS name the console is served on")
	country := fs.String("country", "", "two-letter code of the country this install keeps data in, e.g. us, gb, de, ae (asked if left out)")
	joinCode := fs.String("join", "", "Enterprise: the join code from the primary install's console, to link this install to it")
	primary := fs.String("primary", "", "Enterprise: the primary install's address, e.g. https://vault.example.com")
	fs.Parse(args)
	cc, err := installCountry(*country, os.Stdin, os.Stdout)
	if err != nil {
		return err
	}
	if (*joinCode == "") != (*primary == "") {
		return errors.New("--join and --primary go together: both come from the primary install's console")
	}
	if *primary != "" && !strings.HasPrefix(*primary, "https://") {
		return errors.New("--primary must be an https:// address")
	}
	path := *dir + "/.env"
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite secrets", path)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	userPub, userPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	licence := ""
	if *lic != "" {
		b, err := os.ReadFile(*lic)
		if err != nil {
			return err
		}
		licence = strings.TrimSpace(string(b))
	}
	bootstrap := secret(24)
	lines := []string{
		"# Generated by rv init. Keep this file out of version control and backups of app config.",
		"RV_ENV=production",
		"RV_HOST=" + *host,
		"# Where this install keeps data. Every vault on it lives in this country; it cannot change later.",
		"RV_COUNTRY=" + cc,
		"# Enterprise: the primary install this one reports to. Only names, settings and counts are sent.",
		"RV_PRIMARY_URL=" + *primary,
		"RV_JOIN_CODE=" + *joinCode,
		"DB_PASSWORD=" + secret(24),
		"RV_VAULT_DB_PASSWORD=" + secret(24),
		"RV_CONTROL_DB_PASSWORD=" + secret(24),
		"RV_INTERNAL_TOKEN=" + secret(32),
		"RV_TOKEN_SIGNING_SEED=" + base64.StdEncoding.EncodeToString(seed),
		"RV_USER_TOKEN_SEED=" + base64.StdEncoding.EncodeToString(userPriv.Seed()),
		"RV_USER_TOKEN_PUBLIC_KEY=" + base64.StdEncoding.EncodeToString(userPub),
		"RV_CONTROL_SECRET=" + secret(32),
		"RV_ADAPTER_SECRET=" + secret(32),
		"RV_BOOTSTRAP_TOKEN=" + bootstrap,
		"RV_LICENCE=" + licence,
		"# Written by `rv keys init`:",
		"OPENBAO_TOKEN=",
		"# Observability (optional, --profile observability): Grafana at https://<host>/grafana/.",
		"RV_GRAFANA_ADMIN_PASSWORD=" + secret(18),
		"# How long Loki keeps logs and Prometheus keeps metrics.",
		"RV_LOG_RETENTION=720h",
		"RV_METRICS_RETENTION=30d",
		"# A metrics key from the console (Health & alerts, Metrics, Create key), for Prometheus.",
		"RV_METRICS_KEY=",
	}
	if err := tlsutil.IssueAll(*dir+"/internal-tls", 10*365*24*time.Hour); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Printf("Wrote %s (mode 600).\nBootstrap token for the first admin: %s\nGrafana (optional observability profile): user admin, password in .env as RV_GRAFANA_ADMIN_PASSWORD.\n", path, bootstrap)
	return nil
}

func cmdMigrate() error {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return errors.New("DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var err error
	var applied []string
	// An expired licence stops upgrades, never access: an up-to-date database
	// migrates as a no-op and the product keeps running.
	if blob := os.Getenv("RV_LICENCE"); blob != "" {
		if key, err := license.BuiltInKey(); err == nil {
			if l, err := license.Verify(blob, key); err == nil && l.Expired(time.Now()) {
				if pending, err := store.Pending(ctx, url); err == nil && len(pending) > 0 {
					// A fresh install has every migration pending and the schema absent;
					// only a database with an applied schema counts as an upgrade.
					if len(pending) < countMigrations() {
						return fmt.Errorf("licence expired %s: this upgrade is refused. The installed version keeps running", l.ExpiresAt.Format("2006-01-02"))
					}
				}
			}
		}
	}
	// The database may still be starting when Compose runs this container.
	for attempt := 0; attempt < 30; attempt++ {
		applied, err = store.Migrate(ctx, url, os.Getenv("RV_VAULT_DB_PASSWORD"), os.Getenv("RV_CONTROL_DB_PASSWORD"))
		if err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return errors.New("migration failed; check DATABASE_URL and database logs")
	}
	fmt.Printf("migrations applied: %d\n", len(applied))
	for _, a := range applied {
		fmt.Println(" ", a)
	}
	return nil
}

func countMigrations() int {
	names, _ := fs.Glob(migrations.FS, "*.sql")
	return len(names)
}

// ---- keys --------------------------------------------------------------------

func baoAddr() string {
	if v := os.Getenv("OPENBAO_ADDR"); v != "" {
		return v
	}
	return "http://127.0.0.1:8200"
}

func bao(method, path, token string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, baoAddr()+path, rd)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	client, err := tlsutil.Client("", "", os.Getenv("OPENBAO_CACERT"), 15*time.Second)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		// OpenBao's error text is operational and carries no key material.
		var e struct {
			Errors []string `json:"errors"`
		}
		json.Unmarshal(data, &e)
		return fmt.Errorf("openbao %s returned %d: %s", path, resp.StatusCode, strings.Join(e.Errors, "; "))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

const kekPolicy = `path "transit/encrypt/rv-kek" { capabilities = ["update"] }
path "transit/decrypt/rv-kek" { capabilities = ["update"] }
path "transit/rewrap/rv-kek" { capabilities = ["update"] }
path "transit/keys/rv-kek/rotate" { capabilities = ["update"] }
path "transit/keys/rv-kek" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }`

func cmdKeys(args []string) error {
	if len(args) == 0 {
		return errors.New("rv keys init|unseal|status")
	}
	switch args[0] {
	case "status":
		var st map[string]any
		if err := bao("GET", "/v1/sys/seal-status", "", nil, &st); err != nil {
			return err
		}
		fmt.Printf("initialized=%v sealed=%v shares=%v threshold=%v progress=%v\n", st["initialized"], st["sealed"], st["n"], st["t"], st["progress"])
		return nil
	case "init":
		return keysInit(args[1:])
	case "unseal":
		return keysUnseal(args[1:])
	}
	return errors.New("rv keys init|unseal|status")
}

func unseal(share string) (bool, error) {
	var st struct {
		Sealed bool `json:"sealed"`
	}
	err := bao("POST", "/v1/sys/unseal", "", map[string]string{"key": share}, &st)
	return st.Sealed, err
}

// keysInit runs the key-holder ceremony. Shares are printed once and never stored;
// the root token is revoked after setup, leaving only a narrow vault-api token.
func keysInit(args []string) error {
	fs := flag.NewFlagSet("keys init", flag.ExitOnError)
	envPath := fs.String("env", ".env", "env file that receives the vault-api token")
	sharesOut := fs.String("shares-file", "", "development only: write shares to this file instead of the screen")
	fs.Parse(args)
	var res struct {
		Keys  []string `json:"keys"`
		Token string   `json:"root_token"`
	}
	if err := bao("POST", "/v1/sys/init", "", map[string]int{"secret_shares": 5, "secret_threshold": 3}, &res); err != nil {
		return fmt.Errorf("init failed (already initialised?): %w", err)
	}
	if *sharesOut != "" {
		if err := os.WriteFile(*sharesOut, []byte(strings.Join(res.Keys, "\n")+"\n"), 0o600); err != nil {
			return err
		}
	} else {
		fmt.Println("UNSEAL KEY SHARES. Give one to each of 5 named key holders, now. Any 3 unseal.")
		fmt.Println("They are shown once and stored nowhere. Losing them means losing the data.")
		for i, k := range res.Keys {
			fmt.Printf("  share %d: %s\n", i+1, k)
		}
	}
	for _, k := range res.Keys[:3] {
		if _, err := unseal(k); err != nil {
			return err
		}
	}
	root := res.Token
	if err := bao("POST", "/v1/sys/mounts/transit", root, map[string]string{"type": "transit"}, nil); err != nil {
		return err
	}
	if err := bao("POST", "/v1/transit/keys/rv-kek", root, map[string]any{"type": "aes256-gcm96", "derived": false, "exportable": false, "allow_plaintext_backup": false}, nil); err != nil {
		return err
	}
	if err := bao("POST", "/v1/sys/policies/acl/rv-vault", root, map[string]string{"policy": kekPolicy}, nil); err != nil {
		return err
	}
	var tok struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := bao("POST", "/v1/auth/token/create", root, map[string]any{"policies": []string{"rv-vault"}, "no_default_policy": true, "ttl": "8760h", "renewable": true, "no_parent": true, "display_name": "vault-api"}, &tok); err != nil {
		return err
	}
	if err := setEnv(*envPath, "OPENBAO_TOKEN", tok.Auth.ClientToken); err != nil {
		return err
	}
	if err := bao("POST", "/v1/auth/token/revoke-self", root, map[string]string{}, nil); err != nil {
		return err
	}
	fmt.Printf("Key service ready. KEK created inside OpenBao (not exportable). Root token revoked. Scoped token written to %s.\n", *envPath)
	fmt.Println("Restart vault-api so that it picks up the token.")
	return nil
}

func setEnv(path, key, value string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var out []string
	found := false
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if strings.HasPrefix(line, key+"=") {
			line = key + "=" + value
			found = true
		}
		out = append(out, line)
	}
	if !found {
		out = append(out, key+"="+value)
	}
	return os.WriteFile(path, []byte(strings.Join(out, "\n")+"\n"), 0o600)
}

func keysUnseal(args []string) error {
	shares := args
	if len(shares) == 0 {
		fmt.Println("Enter unseal shares, one per line (needs any 3):")
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			s := strings.TrimSpace(sc.Text())
			if s == "" {
				continue
			}
			sealed, err := unseal(s)
			if err != nil {
				return err
			}
			if !sealed {
				fmt.Println("Unsealed.")
				return nil
			}
			fmt.Println("Share accepted; more needed.")
		}
		return errors.New("still sealed")
	}
	for _, s := range shares {
		sealed, err := unseal(s)
		if err != nil {
			return err
		}
		if !sealed {
			fmt.Println("Unsealed.")
			return nil
		}
	}
	return errors.New("still sealed; more shares are needed")
}

// ---- doctor ------------------------------------------------------------------

func loadEnv(path string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.IndexByte(line, '='); i > 0 && !strings.HasPrefix(line, "#") {
			out[line[:i]] = line[i+1:]
		}
	}
	return out
}

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	envPath := fs.String("env", ".env", "env file")
	url := fs.String("url", "https://localhost", "edge URL")
	insecure := fs.Bool("insecure", false, "accept a self-signed certificate (pilot only)")
	connect := fs.String("connect", "", "dial this host:port instead of the URL's host")
	fs.Parse(args)
	env := loadEnv(*envPath)
	failed := 0
	check := func(name string, err error) {
		if err != nil {
			failed++
			fmt.Printf("FAIL  %-22s %v\n", name, err)
			return
		}
		fmt.Printf("PASS  %-22s\n", name)
	}
	fmt.Printf("Onshore doctor, %s\n\n", time.Now().UTC().Format(time.RFC3339))
	st, err := os.Stat(*envPath)
	if err == nil && st.Mode().Perm()&0o077 != 0 {
		err = fmt.Errorf("%s is readable by others (mode %o)", *envPath, st.Mode().Perm())
	}
	check("env file permissions", err)
	var missing []string
	for _, k := range []string{"DB_PASSWORD", "RV_VAULT_DB_PASSWORD", "RV_CONTROL_DB_PASSWORD", "RV_INTERNAL_TOKEN", "RV_TOKEN_SIGNING_SEED", "RV_USER_TOKEN_SEED", "RV_CONTROL_SECRET", "OPENBAO_TOKEN"} {
		if env[k] == "" {
			missing = append(missing, k)
		}
	}
	err = nil
	if len(missing) > 0 {
		err = fmt.Errorf("missing %s", strings.Join(missing, ", "))
	}
	check("required secrets", err)

	client := doctorClient(*insecure, *connect)
	resp, err := client.Get(*url + "/healthz")
	var health map[string]any
	if err == nil {
		defer resp.Body.Close()
		date, derr := http.ParseTime(resp.Header.Get("Date"))
		if json.NewDecoder(resp.Body).Decode(&health) != nil {
			err = errors.New("unexpected response from the vault API")
		} else if resp.StatusCode != 200 {
			err = fmt.Errorf("vault API status %d: %v", resp.StatusCode, health)
		}
		check("TLS and vault API", err)
		tlsErr := error(nil)
		if resp.TLS == nil {
			tlsErr = errors.New("the edge did not use TLS")
		} else if resp.TLS.Version < 0x0304 {
			tlsErr = errors.New("the edge negotiated below TLS 1.3")
		}
		check("TLS 1.3", tlsErr)
		dbErr, keyErr := error(nil), error(nil)
		if health["database"] != "ok" {
			dbErr = fmt.Errorf("database: %v", health["database"])
		}
		if health["keys"] != "ok" {
			keyErr = errors.New("key service unavailable or sealed; run rv keys unseal")
		}
		check("database", dbErr)
		check("key service", keyErr)
		clockErr := derr
		if derr == nil {
			if d := time.Since(date); d > time.Minute || d < -time.Minute {
				clockErr = fmt.Errorf("clock differs from the server by %s", d.Round(time.Second))
			}
		}
		check("clock", clockErr)
	} else {
		check("TLS and vault API", err)
	}
	if internal, err := client.Post(*url+"/internal/stats", "application/json", strings.NewReader("{}")); err == nil {
		internal.Body.Close()
		e := error(nil)
		if internal.StatusCode != 404 {
			e = fmt.Errorf("edge exposes /internal (status %d)", internal.StatusCode)
		}
		check("internal API not exposed", e)
	}
	lic := env["RV_LICENCE"]
	if lic == "" {
		// Community needs no licence; it isn't a failure.
		if _, err := license.BuiltInKey(); err != nil {
			fmt.Printf("INFO  %-22s %s\n", "licence", "development build: paid features on for development and testing")
		} else {
			fmt.Printf("INFO  %-22s %s\n", "licence", "none: Community edition")
		}
	} else if key, err := license.BuiltInKey(); err != nil {
		check("licence", err)
	} else if l, err := license.Verify(lic, key); err != nil {
		check("licence", err)
	} else if l.Expired(time.Now()) {
		check("licence", fmt.Errorf("expired %s: the product keeps running, upgrades stop", l.ExpiresAt.Format("2006-01-02")))
	} else {
		check("licence", nil)
	}
	fmt.Println()
	if failed > 0 {
		return fmt.Errorf("%d check(s) failed", failed)
	}
	fmt.Println("All checks passed.")
	return nil
}

// ---- scan --------------------------------------------------------------------

type noTokens struct{}

func (noTokens) Tokenize(context.Context, string, string, []logproc.Item) ([]string, error) {
	return nil, errors.New("unused in shadow mode")
}

// cmdScan is the sales demo: point it at a log file and see what would have left
// the country. It runs offline. Samples are masked, so the report is safe to share.
// It looks for every country's data unless --packs narrows it.
func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	packFlag := fs.String("packs", "", "country packs to use, e.g. gb,eu or ng (default: every pack)")
	fs.Parse(args)
	args = fs.Args()
	if len(args) != 1 {
		return errors.New("rv scan [--packs gb,eu] <file|->")
	}
	packs := detect.AllPacks()
	if *packFlag != "" {
		packs = append([]string{"everywhere"}, strings.Split(strings.ToLower(*packFlag), ",")...)
	}
	var r io.Reader = os.Stdin
	if args[0] != "-" {
		f, err := os.Open(args[0])
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}
	rules := detect.BaseRuleSet(detect.New(detect.Config{})).WithPacks("", packs)
	counts := map[detect.EntityType]int64{}
	samples := map[detect.EntityType]string{}
	unique := map[detect.EntityType]map[[32]byte]struct{}{}
	var lines, affected int64
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), logproc.MaxLeafBytes)
	for sc.Scan() {
		lines++
		line := sc.Text()
		ents, _ := rules.Split(rules.ScanFor("logs", "", line, ""))
		if len(ents) > 0 {
			affected++
		}
		for _, e := range ents {
			counts[e.Type]++
			val := line[e.Start:e.End]
			if unique[e.Type] == nil {
				unique[e.Type] = map[[32]byte]struct{}{}
			}
			unique[e.Type][sha256.Sum256([]byte(val))] = struct{}{}
			if _, ok := samples[e.Type]; !ok {
				samples[e.Type] = mask.Value(string(e.Type), "default", val)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	fmt.Printf("Scanned %d lines. %d (%.1f%%) contain identifiers that would leave the country as written.\n\n", lines, affected, pct(affected, lines))
	types := make([]detect.EntityType, 0, len(counts))
	for t := range counts {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool { return counts[types[i]] > counts[types[j]] })
	fmt.Printf("%-18s %10s %10s  %s\n", "ENTITY", "FOUND", "UNIQUE", "MASKED SAMPLE")
	for _, t := range types {
		fmt.Printf("%-18s %10d %10d  %s\n", t, counts[t], len(unique[t]), samples[t])
	}
	fmt.Println("\nNothing was changed or sent. Detection is an estimate: review it against your own log formats.")
	return nil
}

func pct(a, b int64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) * 100 / float64(b)
}

func cmdSAKeygen() error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	fmt.Printf("public_key:  %s\nprivate_key: %s\n\nRegister the public key in the console. Keep the private key in your own secret store.\n", base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv.Seed()))
	return nil
}

// ---- licence -----------------------------------------------------------------

func cmdLicense(args []string) error {
	if len(args) == 0 {
		return errors.New("rv license keygen|sign|verify")
	}
	switch args[0] {
	case "keygen":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		fmt.Printf("public (build with -X onshore/data-plane/internal/license.PublicKeyB64=...): %s\nprivate (vendor only): %s\n", base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv.Seed()))
		return nil
	case "sign":
		fs := flag.NewFlagSet("sign", flag.ExitOnError)
		keyFile := fs.String("key", "", "file holding the base64 private seed")
		customer := fs.String("customer", "", "customer name")
		modules := fs.String("modules", "logs", "comma-separated modules")
		days := fs.Int("days", 365, "validity in days")
		seats := fs.Int("seats", 0, "seats (0 = unlimited)")
		records := fs.Int64("max-records", 0, "protected records (0 = unlimited)")
		fs.Parse(args[1:])
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return errors.New("bad private key file")
		}
		blob, err := license.Sign(license.Licence{Customer: *customer, Modules: strings.Split(*modules, ","), Seats: *seats, MaxRecords: *records, ExpiresAt: time.Now().AddDate(0, 0, *days).UTC()}, ed25519.NewKeyFromSeed(seed))
		if err != nil {
			return err
		}
		fmt.Println(blob)
		return nil
	case "verify":
		if len(args) != 2 {
			return errors.New("rv license verify <file>")
		}
		b, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		key, err := license.BuiltInKey()
		if err != nil {
			return err
		}
		l, err := license.Verify(string(b), key)
		if err != nil {
			return err
		}
		fmt.Printf("%+v\nexpired: %v\n", l, l.Expired(time.Now()))
		return nil
	}
	return errors.New("rv license keygen|sign|verify")
}

// ---- release bundle ----------------------------------------------------------

// cmdBundle signs SHA256SUMS with the vendor key and verifies it against the key
// built into this binary, offline. `verify` also recomputes every listed checksum.
func cmdBundle(args []string) error {
	if len(args) < 2 {
		return errors.New("rv bundle sign <dir> <private-key-file> | rv bundle verify <dir>")
	}
	sums := filepath.Join(args[1], "SHA256SUMS")
	data, err := os.ReadFile(sums)
	if err != nil {
		return err
	}
	switch args[0] {
	case "sign":
		if len(args) != 3 {
			return errors.New("rv bundle sign <dir> <private-key-file>")
		}
		b, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return errors.New("bad private key file")
		}
		return os.WriteFile(sums+".sig", []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), data))+"\n"), 0o644)
	case "verify":
		key, err := license.BuiltInKey()
		if err != nil {
			return err
		}
		sigB64, err := os.ReadFile(sums + ".sig")
		if err != nil {
			return errors.New("this bundle is unsigned: refusing it")
		}
		sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
		if err != nil || !ed25519.Verify(key, data, sig) {
			return errors.New("the bundle signature is invalid: refusing it")
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			parts := strings.Fields(line)
			if len(parts) != 2 || strings.Contains(parts[1], "..") || filepath.IsAbs(parts[1]) {
				return errors.New("malformed SHA256SUMS")
			}
			f, err := os.Open(filepath.Join(args[1], parts[1]))
			if err != nil {
				return err
			}
			h := sha256.New()
			_, err = io.Copy(h, f)
			f.Close()
			if err != nil {
				return err
			}
			if hex.EncodeToString(h.Sum(nil)) != parts[0] {
				return fmt.Errorf("%s does not match its checksum: refusing it", parts[1])
			}
		}
		fmt.Println("Bundle signature and checksums verified.")
		return nil
	}
	return errors.New("rv bundle sign|verify")
}

// ---- support bundle ----------------------------------------------------------

var secretLine = regexp.MustCompile(`(?i)(password|secret|token|seed|key|licence)=.*`)

// cmdSupportBundle collects diagnostics. Secrets are stripped from configuration,
// and logs pass through the detection engine before anything is written.
func cmdSupportBundle() error {
	out := fmt.Sprintf("rv-support-%s.tar.gz", time.Now().UTC().Format("20060102-150405"))
	f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	add := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: time.Now()}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if b, err := os.ReadFile(".env"); err == nil {
		if err := add("env.redacted", secretLine.ReplaceAll(b, []byte("$1=[removed]"))); err != nil {
			return err
		}
	}
	for name, cmdline := range map[string][]string{
		"docker-version.txt": {"docker", "version"},
		"compose-ps.txt":     {"docker", "compose", "ps", "-a"},
		"compose-images.txt": {"docker", "compose", "images"},
	} {
		o, _ := exec.Command(cmdline[0], cmdline[1:]...).CombinedOutput()
		if err := add(name, o); err != nil {
			return err
		}
	}
	rules := detect.GlobalRuleSet(detect.New(detect.Config{}))
	logs, _ := exec.Command("docker", "compose", "logs", "--no-color", "--since", "1h").CombinedOutput()
	var clean bytes.Buffer
	for _, line := range strings.Split(string(logs), "\n") {
		ents, _ := rules.Split(rules.ScanFor("logs", "", line, ""))
		clean.WriteString(detect.Replace(line, ents, func(e detect.Entity, _ string) string { return "[" + string(e.Type) + "]" }))
		clean.WriteByte('\n')
	}
	if err := add("logs-last-hour.redacted.txt", clean.Bytes()); err != nil {
		return err
	}
	sum := sha256.Sum256(clean.Bytes())
	fmt.Printf("Wrote %s. Review it before sending. Log digest %s\n", out, hex.EncodeToString(sum[:8]))
	return nil
}

// cmdAdminRecover is the way back in when every admin is locked out. It needs the database
// credentials, so it is for whoever runs the server. It clears the admin's two-factor when the
// link is used, and leaves a permanent audit entry.
func cmdAdminRecover(args []string) error {
	fs := flag.NewFlagSet("admin-recover", flag.ExitOnError)
	email := fs.String("email", "", "the admin's email address")
	reason := fs.String("reason", "", "why this is needed; goes in the audit log")
	_ = fs.Parse(args)
	if *email == "" || len(*reason) < 5 {
		return errors.New("use: rv admin-recover -email <address> -reason <why, for the audit log>")
	}
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return errors.New("DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := store.Open(ctx, url)
	if err != nil {
		return errors.New("could not reach the database")
	}
	defer pool.Close()
	token := secret(32)
	sum := sha256.Sum256([]byte(token))
	idBytes := make([]byte, 10)
	if _, err := rand.Read(idBytes); err != nil {
		return err
	}
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		var id, tenant string
		err := tx.QueryRow(ctx, `SELECT p.id, p.tenant_id FROM control.principals p
			JOIN control.role_assignments ra ON ra.principal_id=p.id JOIN control.roles r ON r.id=ra.role_id
			WHERE p.email=lower($1) AND p.kind='user' AND p.status='active' AND r.name='admin'`, *email).Scan(&id, &tenant)
		if err != nil {
			return errors.New("no active admin has that email address")
		}
		if _, err := tx.Exec(ctx, `UPDATE control.account_tokens SET revoked_at=now() WHERE principal_id=$1 AND kind='admin_recovery' AND used_at IS NULL AND revoked_at IS NULL`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO control.account_tokens(id,tenant_id,principal_id,kind,token_hash,created_by,expires_at)
			VALUES ($1,$2,$3,'admin_recovery',$4,'operator',now()+interval '1 hour')`, "atk_"+hex.EncodeToString(idBytes), tenant, id, hex.EncodeToString(sum[:])); err != nil {
			return err
		}
		detail, _ := json.Marshal(map[string]string{"principal": id, "reason": *reason})
		return audit.Append(ctx, tx, tenant, []audit.Event{{EventID: uuid4(), TenantID: tenant, OccurredAt: time.Now().UTC(), PrincipalKind: "operator", Module: "control", Action: "admin_recovery_issued", Detail: string(detail)}})
	})
	if err != nil {
		return err
	}
	fmt.Printf("One-time link, valid for 1 hour. Add it to your console address:\n\n  /account#token=%s\n\nIt sets a new password and clears this admin's two-factor. Pass it on securely.\n", token)
	return nil
}

func uuid4() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// cmdTLS renews the internal CA and every service's certificate, for example to add
// a service that came later (such as the language-model service) or before the CA
// expires. The old set is kept beside the new one until the operator removes it.
func cmdTLS(args []string) error {
	if len(args) == 0 || args[0] != "renew" {
		return errors.New("usage: rv tls renew [-dir .]")
	}
	fs := flag.NewFlagSet("tls renew", flag.ExitOnError)
	dir := fs.String("dir", ".", "the directory holding internal-tls")
	fs.Parse(args[1:])
	cur := filepath.Join(*dir, "internal-tls")
	next := cur + ".new"
	os.RemoveAll(next)
	if err := tlsutil.IssueAll(next, 10*365*24*time.Hour); err != nil {
		return err
	}
	old := fmt.Sprintf("%s.old-%s", cur, time.Now().UTC().Format("20060102-150405"))
	if _, err := os.Stat(cur); err == nil {
		if err := os.Rename(cur, old); err != nil {
			return err
		}
	}
	if err := os.Rename(next, cur); err != nil {
		return err
	}
	// Named relative to the install directory: inside the tools container it's /work.
	fmt.Printf("New internal certificates are in internal-tls; the old set is in %s.\nRestart every service so they pick them up:\n  docker compose up -d --force-recreate\nthen unseal the key service (./rv keys unseal) and delete %s.\n", filepath.Base(old), filepath.Base(old))
	return nil
}
