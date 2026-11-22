// Terminates mTLS in front of Next's standalone server, which speaks plain HTTP on
// loopback only. Revealed values therefore never cross the network unencrypted.
import fs from "node:fs";
import net from "node:net";
import tls from "node:tls";

const { RV_TLS_CERT: cert, RV_TLS_KEY: key, RV_TLS_CA: ca } = process.env;
process.env.PORT = "3001";
process.env.HOSTNAME = "127.0.0.1";
await import("./server.js");
if (cert) {
  tls
    .createServer({ cert: fs.readFileSync(cert), key: fs.readFileSync(key), ca: fs.readFileSync(ca), requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.3" }, (client) => {
      const upstream = net.connect(3001, "127.0.0.1");
      client.pipe(upstream).pipe(client);
      const close = () => { client.destroy(); upstream.destroy(); };
      client.on("error", close);
      upstream.on("error", close);
    })
    .listen(3000, "0.0.0.0");
}
