// Operator CLI. Run with Node 22.18+ (runs .ts directly): node scripts/decant.ts <command>
import { buildRequest, makeOperatorToken, USAGE } from './cli-lib.ts';

const argv = process.argv.slice(2);

if (argv[0] === 'op-token' && argv.length === 1) {
  const { token, hash } = await makeOperatorToken();
  console.log(`Operator token (keep it secret; set it as DECANT_OPERATOR_TOKEN):\n${token}\n`);
  console.log('Store its hash in the Worker (paste the hash when prompted):');
  console.log('npx wrangler secret put OPERATOR_TOKEN_HASH');
  console.log(`hash: ${hash}`);
} else if (argv[0] === '--help' || argv[0] === '-h') {
  console.log(USAGE);
} else {
  const req = buildRequest(argv, process.env);
  if ('error' in req) {
    console.error(req.error);
    process.exit(2);
  }
  const res = await fetch(req);
  const text = await res.text();
  if (!res.ok) {
    console.error(`${res.status} ${text}`);
    process.exit(1);
  }
  console.log(text);
}
