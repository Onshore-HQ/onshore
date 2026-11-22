#!/usr/bin/env bash
# Exercises the Go, Java and PHP SDKs against a running e2e install. Each language
# reaches the install through a small TCP relay, so that TLS sees the name "localhost".
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CFG="$1"   # the JSON the end-to-end run writes: sa, kid, seed, vault
read -r SA KID SEED VAULT < <(python3 -I -c "import json,sys;c=json.load(open(sys.argv[1]));print(c['sa'],c['kid'],c['seed'],c['vault'])" "$CFG")
RELAY='socat TCP-LISTEN:8443,fork,reuseaddr TCP:host.docker.internal:8443 &'
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/go" && cat > "$WORK/go/main_test.go" <<GO
package vault
import ("context";"crypto/tls";"net/http";"testing";"time")
func TestLive(t *testing.T) {
 c, err := New("https://localhost:8443","$SA","$KID","$SEED"); if err != nil { t.Fatal(err) }
 c.HTTP = &http.Client{Timeout: 10*time.Second, Transport: &http.Transport{TLSClientConfig:&tls.Config{InsecureSkipVerify:true}}}
 ctx := context.Background()
 r, err := c.Tokenize(ctx,"$VAULT",[]Item{{Field:"bvn",Value:"22666677781"}}); if err != nil || r[0].Token == "" { t.Fatal(err, r) }
 r2, err := c.Tokenize(ctx,"$VAULT",[]Item{{Field:"bvn",Value:"22666677781"}}); if err != nil || r2[0].Token != r[0].Token || !r2[0].Existing { t.Fatal(err, r2) }
 got, err := c.Lookup(ctx,"$VAULT","bvn","22666677781"); if err != nil || got != r[0].Token { t.Fatal(err, got) }
 if _, err := c.Detokenize(ctx,"$VAULT",[]string{r[0].Token},"sdk test"); err == nil { t.Fatal("default deny expected") }
}
GO
cp "$ROOT/sdks/go/client.go" "$ROOT/sdks/go/go.mod" "$WORK/go/"
docker run --rm --add-host host.docker.internal:host-gateway -v "$WORK/go:/w" -w /w golang:1.27.3-bookworm sh -c "apt-get -qq update >/dev/null; apt-get -qq install -y socat >/dev/null 2>&1; $RELAY sleep 1; go test -count=1 ./... 2>&1 | tail -3" | sed 's/^/go:   /'

cat > "$WORK/t.php" <<PHP
<?php
require '/sdk/VaultClient.php';
\$c = new Onshore\VaultClient('https://localhost:8443','$SA','$KID','$SEED',4,[CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_SSL_VERIFYHOST=>0]);
\$r = \$c->tokenize('$VAULT',[['field'=>'bvn','value'=>'22666677782']]);
assert(str_starts_with(\$r[0]['token'],'tok_bvn_'));
\$r2 = \$c->tokenize('$VAULT',[['field'=>'bvn','value'=>'22666677782']]);
if (\$r2[0]['token'] !== \$r[0]['token']) { exit("determinism failed\n"); }
if (\$c->lookup('$VAULT','bvn','22666677782') !== \$r[0]['token']) { exit("lookup failed\n"); }
try { \$c->detokenize('$VAULT',[\$r[0]['token']],'sdk test'); exit("default deny expected\n"); } catch (Onshore\VaultError \$e) { echo "ok ".\$e->errorCode."\n"; }
PHP
docker run --rm --add-host host.docker.internal:host-gateway -v "$WORK/t.php:/t.php:ro" -v "$ROOT/sdks/php/src:/sdk:ro" php:8.3-cli sh -c "apt-get -qq update >/dev/null; apt-get -qq install -y socat libcurl4-openssl-dev >/dev/null 2>&1; docker-php-ext-install -j4 curl >/dev/null 2>&1; $RELAY sleep 1; php /t.php" | sed 's/^/php:  /'

mkdir -p "$WORK/j/ng/onshore"; cp "$ROOT/sdks/java/src/main/java/ng/onshore/VaultClient.java" "$WORK/j/ng/onshore/"
cat > "$WORK/j/T.java" <<JAVA
import ng.onshore.VaultClient; import java.util.List; import javax.net.ssl.*; import java.net.http.HttpClient; import java.security.cert.X509Certificate;
public class T { public static void main(String[] a) throws Exception {
 TrustManager[] tm = { new X509TrustManager(){ public void checkClientTrusted(X509Certificate[] c,String s){} public void checkServerTrusted(X509Certificate[] c,String s){} public X509Certificate[] getAcceptedIssuers(){return new X509Certificate[0];} } };
 SSLContext s = SSLContext.getInstance("TLS"); s.init(null,tm,null);
 System.setProperty("jdk.internal.httpclient.disableHostnameVerification","true");
 var c = new VaultClient("https://localhost:8443","$SA","$KID","$SEED",HttpClient.newBuilder().sslContext(s).build());
 var t = c.tokenize("$VAULT","bvn",List.of("22666677783"));
 if (!t.get(0).startsWith("tok_bvn_")) throw new RuntimeException("token "+t);
 if (!c.tokenize("$VAULT","bvn",List.of("22666677783")).get(0).equals(t.get(0))) throw new RuntimeException("determinism");
 if (!c.lookup("$VAULT","bvn","22666677783").equals(t.get(0))) throw new RuntimeException("lookup");
 try { c.detokenize("$VAULT",t,"sdk test"); var r=c.detokenize("$VAULT",t,"sdk test"); if (!"denied".equals(r.get(0).decision())) throw new RuntimeException("deny "+r); System.out.println("ok denied"); }
 catch (VaultClient.VaultException e) { System.out.println("ok "+e.code); }
}}
JAVA
docker run --rm --add-host host.docker.internal:host-gateway -v "$WORK/j:/w" -w /w eclipse-temurin:21-jdk sh -c "apt-get -qq update >/dev/null; apt-get -qq install -y socat >/dev/null 2>&1; $RELAY sleep 1; javac -d out ng/onshore/VaultClient.java T.java && java -Djdk.internal.httpclient.disableHostnameVerification=true -cp out T" | sed 's/^/java: /'
