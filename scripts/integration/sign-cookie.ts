/**
 * Mints a real CloudFront signed-cookie set using `@aws-sdk/cloudfront-signer`
 * (the same library LibreChat uses) and writes it as JSON to stdout.
 *
 * Usage:
 *   pnpm sign <privateKeyPath> <keyPairId> <resource> --epoch <seconds>
 *   pnpm sign <privateKeyPath> <keyPairId> <resource> [expiresInSeconds]
 *
 * With `--epoch`, `DateLessThan` is set to the given Unix epoch directly (used
 * to mint fixtures with a far-future expiry). Without it, the expiry is
 * "now + expiresInSeconds" (default 1800, matching LibreChat's `cookieExpiry`).
 *
 * Output is a JSON object with the three cookie names:
 *   {"CloudFront-Key-Pair-Id": "...", "CloudFront-Policy": "...", "CloudFront-Signature": "..."}
 */
import { readFileSync } from "node:fs";
import { getSignedCookies } from "@aws-sdk/cloudfront-signer";

function usage(): never {
  console.error(
    "usage: pnpm sign <privateKeyPath> <keyPairId> <resource> [--epoch <seconds>] [expiresInSeconds]",
  );

  process.exit(1);
}

const args = process.argv.slice(2);
const epochIdx = args.indexOf("--epoch");

let privateKeyPath: string;
let keyPairId: string;
let resource: string;
let epoch: number;

if (epochIdx !== -1) {
  privateKeyPath = args[0];
  keyPairId = args[1];
  resource = args[2];
  epoch = Number(args[epochIdx + 1]);

  if (!privateKeyPath || !keyPairId || !resource || !Number.isFinite(epoch)) {
    usage();
  }
} else {
  privateKeyPath = args[0];
  keyPairId = args[1];
  resource = args[2];

  const expiresInSeconds = args[3] ? Number(args[3]) : 1800;

  if (!privateKeyPath || !keyPairId || !resource) {
    usage();
  }

  epoch = Math.floor(Date.now() / 1000) + expiresInSeconds;
}

const privateKey = readFileSync(privateKeyPath, "utf8");

const policy = JSON.stringify({
  Statement: [
    {
      Resource: resource,
      Condition: {
        DateLessThan: {
          "AWS:EpochTime": epoch,
        },
      },
    },
  ],
});

const cookies = getSignedCookies({ keyPairId, privateKey, policy });

console.log(JSON.stringify(cookies));
