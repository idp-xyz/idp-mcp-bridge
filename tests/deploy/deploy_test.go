// Package deploy checks deploy/kubernetes for internal consistency and against the code, with no cluster involved: every
// object is named and namespaced, the pod is hardened, the mounts, ports and settings agree with each other and with what
// the service reads, nothing test-only is shipped, the shipped connections file enables nothing, the network policy
// admits only the gateway, the registry and the Workspace, and the egress policy excludes exactly the IPv4 addresses the
// service refuses to connect to. It cannot show that a CNI enforces the policies: that is the platform's kind run.
package deploy

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"idp-mcp-bridge/internal/addr"
	"idp-mcp-bridge/internal/config"
)

const (
	dir = "../../deploy/kubernetes"
	ns  = "idp-mcp-bridge"
)

type doc = map[string]any

func load(t *testing.T, name string) []doc {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	var out []doc
	for {
		var d doc
		if err := dec.Decode(&d); errors.Is(err, io.EOF) {
			return out
		} else if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d != nil {
			out = append(out, d)
		}
	}
}

func get(d any, path ...string) any {
	for _, p := range path {
		m, ok := d.(doc)
		if !ok {
			return nil
		}
		d = m[p]
	}
	return d
}

func str(d any, path ...string) string { s, _ := get(d, path...).(string); return s }
func list(d any, path ...string) []any { l, _ := get(d, path...).([]any); return l }
func name(d doc) string                { return str(d, "kind") + "/" + str(d, "metadata", "name") }

func strs(l []any) []string {
	var out []string
	for _, v := range l {
		out = append(out, v.(string))
	}
	sort.Strings(out)
	return out
}

type manifests struct {
	kust   doc
	docs   []doc
	byKind map[string][]doc
}

func loadAll(t *testing.T) *manifests {
	t.Helper()
	m := &manifests{kust: load(t, "kustomization.yaml")[0], byKind: map[string][]doc{}}
	for _, r := range list(m.kust, "resources") {
		for _, d := range load(t, r.(string)) {
			m.docs = append(m.docs, d)
			m.byKind[str(d, "kind")] = append(m.byKind[str(d, "kind")], d)
		}
	}
	return m
}

func (m *manifests) one(t *testing.T, kind string) doc {
	t.Helper()
	if len(m.byKind[kind]) != 1 {
		t.Fatalf("%d %s, want one", len(m.byKind[kind]), kind)
	}
	return m.byKind[kind][0]
}

func (m *manifests) policy(t *testing.T, n string) doc {
	t.Helper()
	for _, p := range m.byKind["NetworkPolicy"] {
		if str(p, "metadata", "name") == n {
			return p
		}
	}
	t.Fatalf("no policy %s", n)
	return nil
}

func envOf(container any) map[string]string {
	out := map[string]string{}
	for _, e := range list(container, "env") {
		out[str(e, "name")] = str(e, "value")
	}
	return out
}

func TestKustomizationListsEveryFileAndUsesLabelsNotCommonLabels(t *testing.T) {
	m := loadAll(t)
	if m.kust["commonLabels"] != nil || m.kust["namespace"] != nil {
		t.Error("commonLabels rewrites NetworkPolicy peer selectors (the gateway, kube-dns), which then match nothing")
	}
	listed := map[string]bool{"kustomization.yaml": true}
	for _, r := range list(m.kust, "resources") {
		listed[r.(string)] = true
	}
	for _, g := range list(m.kust, "configMapGenerator") {
		for _, f := range list(g, "files") {
			listed[f.(string)] = true
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !listed[e.Name()] {
			t.Errorf("%s is not used by the kustomization", e.Name())
		}
		if n := strings.ToLower(e.Name()); strings.Contains(n, "key") || strings.Contains(n, "secret") {
			t.Errorf("%s: a key or secret does not belong in the repository", e.Name())
		}
	}
	imgs := list(m.kust, "images")
	if len(imgs) != 1 || str(imgs[0], "name") != "idp-mcp-bridge" || !strings.HasPrefix(str(imgs[0], "digest"), "sha256:") ||
		!strings.HasPrefix(str(imgs[0], "newName"), "registry.example.com/idp/") {
		t.Errorf("the image is not a placeholder pinned by digest: %v", imgs)
	}
}

func TestEveryManifestIsNamedAndInTheNamespace(t *testing.T) {
	m := loadAll(t)
	for _, d := range m.docs {
		if str(d, "apiVersion") == "" || str(d, "kind") == "" || str(d, "metadata", "name") == "" {
			t.Errorf("incomplete object: %v", d)
		}
		switch k := str(d, "kind"); k {
		case "Namespace":
			if str(d, "metadata", "name") != ns {
				t.Errorf("namespace %s", name(d))
			}
		case "Secret", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding", "ServiceAccount":
			t.Errorf("%s does not belong here: the operator creates the secrets, and the service has no credential for the API", name(d))
		default:
			if got := str(d, "metadata", "namespace"); got != ns {
				t.Errorf("%s: namespace %q", name(d), got)
			}
		}
	}
	n := m.one(t, "Namespace")
	l, _ := get(n, "metadata", "labels").(doc)
	if l["pod-security.kubernetes.io/enforce"] != "restricted" || l["idp-mcp/mcp-upstream"] != "true" {
		t.Errorf("namespace labels %v", l)
	}
}

func TestServiceIsHardenedAndItsSettingsAgreeWithItsMountsAndPorts(t *testing.T) {
	m := loadAll(t)
	dep, svc := m.one(t, "Deployment"), m.one(t, "Service")
	pod := get(dep, "spec", "template", "spec")
	if get(pod, "automountServiceAccountToken") != false || get(pod, "enableServiceLinks") != false || get(pod, "hostNetwork") != nil {
		t.Error("the pod mounts a service account token, or has service links or the host network")
	}
	if get(pod, "securityContext", "runAsNonRoot") != true || str(pod, "securityContext", "seccompProfile", "type") != "RuntimeDefault" {
		t.Errorf("pod security context %v", get(pod, "securityContext"))
	}
	cs := list(pod, "containers")
	if len(cs) != 1 {
		t.Fatalf("%d containers", len(cs))
	}
	c := cs[0]
	sc := get(c, "securityContext")
	if get(sc, "allowPrivilegeEscalation") != false || get(sc, "readOnlyRootFilesystem") != true || strings.Join(strs(list(sc, "capabilities", "drop")), ",") != "ALL" ||
		get(c, "resources", "limits", "memory") == nil || get(c, "resources", "limits", "cpu") == nil ||
		get(c, "resources", "requests", "memory") == nil || get(c, "resources", "requests", "cpu") == nil {
		t.Errorf("container %v", c)
	}
	if str(c, "image") != "idp-mcp-bridge" {
		t.Errorf("image %q is not the one the kustomization remaps", str(c, "image"))
	}
	env := envOf(c)
	ports := map[string]int{}
	for _, p := range list(c, "ports") {
		ports[str(p, "name")], _ = get(p, "containerPort").(int)
	}
	if ports["mcp"] != 8680 || ports["api"] != 8681 || ports["ops"] != 9680 || env["IDP_BRIDGE_LISTEN"] != "0.0.0.0:8680" ||
		env["IDP_BRIDGE_API_LISTEN"] != "0.0.0.0:8681" || env["IDP_BRIDGE_METRICS"] != "0.0.0.0:9680" {
		t.Errorf("ports %v, env %v", ports, env)
	}
	if env["IDP_BRIDGE_PRIVATE_NETWORK"] != "true" {
		t.Error("a non-loopback address needs IDP_BRIDGE_PRIVATE_NETWORK=true")
	}
	for probe, path := range map[string]string{"readinessProbe": "/readyz", "livenessProbe": "/healthz"} {
		if str(c, probe, "httpGet", "path") != path || str(c, probe, "httpGet", "port") != "ops" {
			t.Errorf("%s %v is not %s on the ops port", probe, get(c, probe), path)
		}
	}
	sp := list(svc, "spec", "ports")
	if len(sp) != 2 || get(sp[0], "port") != 8680 || str(sp[0], "targetPort") != "mcp" || get(sp[1], "port") != 8681 || str(sp[1], "targetPort") != "api" {
		t.Errorf("service ports %v", sp)
	}
	labels, _ := get(dep, "spec", "template", "metadata", "labels").(doc)
	sel, _ := get(svc, "spec", "selector").(doc)
	dsel, _ := get(dep, "spec", "selector", "matchLabels").(doc)
	if len(sel) != 1 || sel["app.kubernetes.io/component"] != "bridge" || labels["app.kubernetes.io/component"] != "bridge" || dsel["app.kubernetes.io/component"] != "bridge" {
		t.Errorf("selectors: service %v, deployment %v, pod labels %v", sel, dsel, labels)
	}
	// every file the service reads is in a read-only mount of a volume that exists
	mounts := map[string]string{}
	for _, mt := range list(c, "volumeMounts") {
		if get(mt, "readOnly") != true {
			t.Errorf("mount %v is writable", mt)
		}
		mounts[str(mt, "name")] = str(mt, "mountPath")
	}
	vols := map[string]doc{}
	for _, v := range list(pod, "volumes") {
		vols[str(v, "name")] = v.(doc)
	}
	if len(vols) != len(mounts) {
		t.Errorf("%d volumes, %d mounts", len(vols), len(mounts))
	}
	for n := range mounts {
		if vols[n] == nil {
			t.Errorf("mount %s has no volume", n)
		}
	}
	for v, want := range map[string]struct{ volume, key string }{
		"IDP_BRIDGE_CALLER_KEYS_FILE":     {"gateway-caller-keys", "caller.pub"},
		"IDP_BRIDGE_CONFIG_FILE":          {"connections", "connections.yaml"},
		"IDP_BRIDGE_DATABASE_URL_FILE":    {"database", "service-url"},
		"IDP_BRIDGE_ENCRYPTION_KEYS_FILE": {"encryption-keys", "keys"},
	} {
		if p := env[v]; p != mounts[want.volume]+"/"+want.key {
			t.Errorf("%s=%q is not %s/%s", v, p, mounts[want.volume], want.key)
		}
	}
	// the database URL holds a password and the keys seal the tokens: files of the operator's Secrets, never values in the manifest
	for _, v := range []string{"IDP_BRIDGE_DATABASE_URL", "IDP_BRIDGE_ENCRYPTION_KEYS"} {
		if _, set := env[v]; set {
			t.Errorf("%s is in the Deployment's environment", v)
		}
	}
	if str(vols["database"], "secret", "secretName") != "idp-mcp-bridge-database" || str(vols["encryption-keys"], "secret", "secretName") != "idp-mcp-bridge-encryption-keys" {
		t.Errorf("volumes %v", vols)
	}
	if str(vols["gateway-caller-keys"], "configMap", "name") != "idp-mcp-bridge-gateway-caller-keys" || str(vols["client-secrets"], "secret", "secretName") != "idp-mcp-bridge-client-secrets" {
		t.Errorf("volumes %v", vols)
	}
	gen := list(m.kust, "configMapGenerator")
	if len(gen) != 1 || str(gen[0], "name") != str(vols["connections"], "configMap", "name") || len(list(gen[0], "files")) != 1 || list(gen[0], "files")[0] != "connections.yaml" {
		t.Errorf("the connections ConfigMap %q is not the one the kustomization generates: %v", str(vols["connections"], "configMap", "name"), gen)
	}
	// the base URL is the Service's URL as it is registered at the gateway, and the audience of a connection is that and /mcp/<id>
	want := "http://" + str(svc, "metadata", "name") + "." + ns + ".svc.cluster.local:8680"
	if env["IDP_BRIDGE_BASE_URL"] != want {
		t.Errorf("IDP_BRIDGE_BASE_URL=%q, the Service's URL is %q", env["IDP_BRIDGE_BASE_URL"], want)
	}
	for _, f := range []string{"../../README.md", "../../docs/RUNBOOK.md"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), want+"/mcp/") {
			t.Errorf("%s does not document the endpoint form %s/mcp/<id>", f, want)
		}
	}
	// no secret value in the environment
	for k := range env {
		if strings.Contains(k, "SECRET") || strings.Contains(k, "TOKEN") || strings.Contains(k, "PASSWORD") || strings.HasSuffix(k, "_KEY") {
			t.Errorf("%s is in the environment: keys and secrets are files of mounted Secrets", k)
		}
	}
}

// The exemption for test origins is for tests, and a manifest that ships it ships a hole.
func TestNothingTestOnlyIsShipped(t *testing.T) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "IDP_BRIDGE_TEST_ORIGINS") && !(e.Name() == "bridge.yaml" && strings.Contains(line, "Never IDP_BRIDGE_TEST_ORIGINS")) {
				t.Errorf("%s:%d mentions IDP_BRIDGE_TEST_ORIGINS: %s", e.Name(), i+1, line)
			}
		}
	}
	m := loadAll(t)
	env := envOf(list(get(m.one(t, "Deployment"), "spec", "template", "spec"), "containers")[0])
	if _, ok := env["IDP_BRIDGE_TEST_ORIGINS"]; ok {
		t.Error("IDP_BRIDGE_TEST_ORIGINS is set")
	}
	if _, ok := env["IDP_BRIDGE_EGRESS_PROXY"]; ok {
		t.Error("a proxy is the operator's, with its own egress rule: it is not shipped set")
	}
	for _, d := range m.byKind["ConfigMap"] {
		t.Errorf("%s: the only ConfigMap is generated from connections.yaml", name(d))
	}
}

var secretish = regexp.MustCompile(`(?i)(BEGIN [A-Z ]*(PRIVATE|PUBLIC) KEY|[A-Za-z0-9+/]{40,}={0,2}$)`)

func TestNoKeyMaterialInTheFiles(t *testing.T) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		for i, line := range strings.Split(string(b), "\n") {
			if secretish.MatchString(strings.TrimSpace(line)) && !strings.Contains(line, "sha256:") {
				t.Errorf("%s:%d looks like key material: %s", e.Name(), i+1, line)
			}
		}
	}
}

// Nothing is enabled until an operator says so: the shipped file lists no connection, which the service does not start with.
func TestTheShippedConnectionsFileEnablesNothingAndTheServiceDoesNotStartWithIt(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(dir, "connections.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.Parse(b, config.Options{}); err == nil || !strings.Contains(err.Error(), "no connections") {
		t.Fatalf("the shipped file: %v", err)
	}
	// and the example in the commented lines is a file the service accepts, so the instructions in it work
	var ex []string
	for _, l := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(l, "# "); ok && (strings.HasPrefix(rest, "connections:") || strings.HasPrefix(rest, "  ")) {
			ex = append(ex, rest)
		}
	}
	cs, err := config.Parse([]byte(strings.Join(ex, "\n")), config.Options{})
	if err != nil || len(cs) != 1 || cs[0].ID != "docs" {
		t.Fatalf("the example in the file: %v\n%s", err, strings.Join(ex, "\n"))
	}
}

func TestEgressPolicyIsTheOnlyWayOutAndIsIPv4OnlyOnPort443(t *testing.T) {
	m := loadAll(t)
	names := map[string]bool{}
	for _, p := range m.byKind["NetworkPolicy"] {
		for _, ty := range list(p, "spec", "policyTypes") {
			if ty == "Egress" && len(list(p, "spec", "egress")) > 0 {
				names[str(p, "metadata", "name")] = true
			}
		}
	}
	if len(names) != 4 || !names["allow-dns"] || !names["bridge-egress"] || !names["bridge-database"] || !names["bridge-keycloak"] {
		t.Fatalf("policies that allow egress: %v, want allow-dns, bridge-egress, bridge-database and bridge-keycloak", names)
	}
	web := m.policy(t, "bridge-egress")
	sel, _ := get(web, "spec", "podSelector", "matchLabels").(doc)
	if len(sel) != 1 || sel["app.kubernetes.io/component"] != "bridge" {
		t.Errorf("bridge-egress selects %v", sel)
	}
	eg := list(web, "spec", "egress")
	if len(eg) != 1 || len(list(eg[0], "to")) != 1 {
		t.Fatalf("egress %v", eg)
	}
	to := list(eg[0], "to")[0]
	if get(to, "namespaceSelector") != nil || get(to, "podSelector") != nil || str(to, "ipBlock", "cidr") != "0.0.0.0/0" {
		t.Fatalf("egress peer %v: IPv4 addresses outside the cluster only", to)
	}
	var except []netip.Prefix
	for _, c := range list(to, "ipBlock", "except") {
		p := netip.MustParsePrefix(c.(string))
		if !p.Addr().Is4() {
			t.Errorf("except %s is not IPv4", p)
		}
		except = append(except, p)
	}
	excluded := func(a netip.Addr) bool {
		for _, e := range except {
			if e.Contains(a) {
				return true
			}
		}
		return false
	}
	// What the service refuses to connect to, the cluster refuses too, and nothing else: every /24 of the IPv4 space is
	// compared (the smallest block of the table is a /24), so a block added to the code's table and not here is found, and
	// so is an except that cuts off public addresses.
	for n := uint64(0); n < 1<<32; n += 256 {
		a := netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), 0})
		if refused := !addr.Public(a); refused != excluded(a) {
			t.Fatalf("%s: the service refuses it: %v; the policy excludes it: %v", a, refused, excluded(a))
		}
	}
	for _, a := range []string{"0.0.0.0", "10.255.255.254", "127.0.0.1", "169.254.169.254", "192.168.255.254", "255.255.255.255"} {
		if a := netip.MustParseAddr(a); !excluded(a) || addr.Public(a) {
			t.Errorf("%s: excluded %v, public per the code %v", a, excluded(a), addr.Public(a))
		}
	}
	for _, a := range []string{"1.1.1.1", "93.184.216.34", "151.101.0.223"} {
		if excluded(netip.MustParseAddr(a)) {
			t.Errorf("the public address %s is excluded", a)
		}
	}
	// https only: the configuration refuses anything else, so the cluster admits nothing else
	ports := list(eg[0], "ports")
	if len(ports) != 1 || get(ports[0], "port") != 443 || str(ports[0], "protocol") != "TCP" {
		t.Errorf("egress ports %v, want TCP 443 only", ports)
	}
}

func TestIngressAdmitsTheGatewayAndTheRegistryOnTheMCPPortTheWorkspaceOnTheAPIPortAndNobodyElse(t *testing.T) {
	m := loadAll(t)
	rules := list(m.policy(t, "bridge-ingress"), "spec", "ingress")
	if len(rules) != 3 {
		t.Fatalf("ingress %v", rules)
	}
	peers := func(rule any) map[string]string {
		out := map[string]string{}
		for _, f := range list(rule, "from") {
			nsSel, _ := get(f, "namespaceSelector", "matchLabels").(doc)
			podSel, _ := get(f, "podSelector", "matchLabels").(doc)
			if len(nsSel) != 1 || get(f, "ipBlock") != nil {
				t.Errorf("peer %v", f)
			}
			c, _ := podSel["app.kubernetes.io/component"].(string)
			out[nsSel["kubernetes.io/metadata.name"].(string)+"/"+c] = ""
		}
		return out
	}
	mcp := peers(rules[0])
	_, gw := mcp["idp-mcp/gateway"]
	_, reg := mcp["idp-mcp/registry"]
	if len(mcp) != 2 || !gw || !reg {
		t.Errorf("MCP peers %v", mcp)
	}
	if _, ok := mcp["idp-workspace/workspace"]; ok {
		t.Error("the Workspace reaches the MCP port")
	}
	if p := list(rules[0], "ports"); len(p) != 1 || get(p[0], "port") != 8680 {
		t.Errorf("ports %v", p)
	}
	api := peers(rules[1])
	if _, ok := api["idp-workspace/workspace"]; !ok || len(api) != 1 {
		t.Errorf("API peers %v: the Workspace only", api)
	}
	if p := list(rules[1], "ports"); len(p) != 1 || get(p[0], "port") != 8681 {
		t.Errorf("API ports %v", p)
	}
	for _, f := range list(rules[2], "from") {
		if nsSel, _ := get(f, "namespaceSelector", "matchLabels").(doc); nsSel["kubernetes.io/metadata.name"] != "observability" {
			t.Errorf("ops peer %v", f)
		}
	}
	if p := list(rules[2], "ports"); len(p) != 1 || get(p[0], "port") != 9680 {
		t.Errorf("ops ports %v", p)
	}
	// default deny of both directions stays
	deny := m.policy(t, "default-deny")
	if len(get(deny, "spec", "podSelector").(doc)) != 0 || len(strs(list(deny, "spec", "policyTypes"))) != 2 || get(deny, "spec", "ingress") != nil || get(deny, "spec", "egress") != nil {
		t.Error("no default-deny of both directions")
	}
}

// The example in the README is a file the service accepts, so that what an operator copies from it works.
func TestTheExampleInTheREADMEIsAValidConnectionsFile(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(b), "```yaml\n")
	if !ok {
		t.Fatal("no yaml block in the README")
	}
	block, _, _ := strings.Cut(rest, "```")
	cs, err := config.Parse([]byte(block), config.Options{})
	if err != nil || len(cs) != 2 || cs[0].ID != "github" || cs[1].Authorization.Mode != config.AuthNone {
		t.Fatalf("%v\n%s", err, block)
	}
}

// What the pods may reach inside the cluster: PostgreSQL and Keycloak's keys, by labels and ports; no address range.
func TestTheDatabaseAndKeycloakAreTheOnlyPlacesInTheClusterTheBridgeMayReach(t *testing.T) {
	m := loadAll(t)
	for name, want := range map[string]struct {
		ns, label, value string
		port             int
	}{
		"bridge-database": {"databases", "app.kubernetes.io/name", "postgresql", 5432},
		"bridge-keycloak": {"keycloak", "app.kubernetes.io/name", "keycloak", 8443},
	} {
		p := m.policy(t, name)
		sel, _ := get(p, "spec", "podSelector", "matchLabels").(doc)
		eg := list(p, "spec", "egress")
		if name == "bridge-database" { // the service and the migration Job
			ex := list(p, "spec", "podSelector", "matchExpressions")
			if len(ex) != 1 || str(ex[0], "key") != "app.kubernetes.io/component" || strings.Join(strs(list(ex[0], "values")), ",") != "bridge,migrate" {
				t.Fatalf("%s selects %v", name, ex)
			}
			sel = doc{"app.kubernetes.io/component": "bridge"}
		}
		if len(sel) != 1 || sel["app.kubernetes.io/component"] != "bridge" || len(eg) != 1 || len(list(eg[0], "to")) != 1 {
			t.Fatalf("%s: %v", name, p)
		}
		to := list(eg[0], "to")[0]
		nsSel, _ := get(to, "namespaceSelector", "matchLabels").(doc)
		podSel, _ := get(to, "podSelector", "matchLabels").(doc)
		ports := list(eg[0], "ports")
		if get(to, "ipBlock") != nil || nsSel["kubernetes.io/metadata.name"] != want.ns || podSel[want.label] != want.value || len(ports) != 1 || get(ports[0], "port") != want.port {
			t.Errorf("%s: %v", name, to)
		}
	}
}

// ADR-0001 D25: the owner's URL is the migration Job's alone, the Deployment has the app role's URL only, and the Job is as
// hardened as the service and reaches the database and nothing else.
func TestTheMigrationJobHoldsTheOwnersURLAndTheServiceNeverDoes(t *testing.T) {
	m := loadAll(t)
	job, dep := m.one(t, "Job"), m.one(t, "Deployment")
	pod := get(job, "spec", "template", "spec")
	cs := list(pod, "containers")
	if len(cs) != 1 || str(cs[0], "image") != "idp-mcp-bridge" || strings.Join(strs(list(cs[0], "args")), " ") != "migrate" {
		t.Fatalf("containers %v", cs)
	}
	sc := get(cs[0], "securityContext")
	if get(pod, "automountServiceAccountToken") != false || get(pod, "securityContext", "runAsNonRoot") != true || get(sc, "allowPrivilegeEscalation") != false ||
		get(sc, "readOnlyRootFilesystem") != true || strings.Join(strs(list(sc, "capabilities", "drop")), ",") != "ALL" {
		t.Errorf("the Job is not hardened: %v", pod)
	}
	env := envOf(cs[0])
	if env["IDP_BRIDGE_MIGRATION_DATABASE_URL_FILE"] != "/etc/idp/database-owner/owner-url" || len(list(pod, "volumes")) != 1 ||
		str(list(pod, "volumes")[0], "secret", "secretName") != "idp-mcp-bridge-database-owner" {
		t.Errorf("env %v, volumes %v", env, list(pod, "volumes"))
	}
	dpod := get(dep, "spec", "template", "spec")
	for _, v := range list(dpod, "volumes") {
		if str(v, "secret", "secretName") == "idp-mcp-bridge-database-owner" {
			t.Error("the Deployment mounts the schema owner's credentials: the server must run as the least-privilege role")
		}
	}
	for k := range envOf(list(dpod, "containers")[0]) {
		if strings.Contains(k, "MIGRATION") || strings.Contains(k, "APP_DB_PASSWORD") {
			t.Errorf("the Deployment's environment has %s", k)
		}
	}
	if lab, _ := get(job, "spec", "template", "metadata", "labels").(doc); lab["app.kubernetes.io/component"] != "migrate" {
		t.Errorf("labels %v: the network policy names the Job by its component", lab)
	}
	// nothing else of the manifests names the owner's Secret
	for _, d := range m.docs {
		if name(d) != name(job) && strings.Contains(asYAML(d), "database-owner") {
			t.Errorf("%s mentions the owner's Secret", name(d))
		}
	}
}

func asYAML(d doc) string { b, _ := yaml.Marshal(d); return string(b) }

// The server never runs DDL: the migrations are applied only by the `migrate` command (the Job), which is the one caller of
// grants.Migrate outside the tests.
func TestOnlyTheMigrateCommandAppliesMigrations(t *testing.T) {
	var callers []string
	err := filepath.Walk("../..", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.Contains(path, "/pgtest/") || strings.Contains(path, "internal/grants/") {
			return nil
		}
		b, _ := os.ReadFile(path)
		for i := 0; i < strings.Count(string(b), "grants.Migrate("); i++ {
			callers = append(callers, filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(callers) != 1 || !strings.HasSuffix(callers[0], "cmd/idp-mcp-bridge/oauth.go") {
		t.Fatalf("grants.Migrate is called from %v", callers)
	}
}
