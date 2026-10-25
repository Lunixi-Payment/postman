'use strict';

// Checks every Postman file in this repository:
// - collections are valid JSON in the Postman v2.1 format,
// - environment templates parse and carry no secret value (key material,
//   tokens and secrets stay empty; key ids stay placeholders).

const fs = require('node:fs');
const path = require('node:path');

const SECRET_KEY = /(private_key|secret|access_token|password|api_key|token)$/i;
const PLACEHOLDER_KEY_ID = /^(|mk_(live|test)_sk_\.\.\.)$/;

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    if (entry.name === '.git' || entry.name === 'node_modules') return [];
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? walk(full) : [full];
  });
}

const problems = [];
const files = walk('.');
const collections = files.filter((f) => f.endsWith('.postman_collection.json'));
const environments = files.filter((f) => f.endsWith('.postman_environment.json'));

for (const file of collections) {
  const collection = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!String(collection.info && collection.info.schema).includes('/collection/v2.1')) {
    problems.push(`${file}: not a Postman v2.1 collection`);
  }
}

for (const file of environments) {
  const environment = JSON.parse(fs.readFileSync(file, 'utf8'));
  for (const variable of environment.values || []) {
    const value = String(variable.value ?? '');
    if (variable.key === 'key_id' && !PLACEHOLDER_KEY_ID.test(value)) {
      problems.push(`${file}: key_id must stay a placeholder`);
    } else if (SECRET_KEY.test(variable.key) && value !== '') {
      problems.push(`${file}: ${variable.key} must be empty`);
    }
  }
}

if (collections.length === 0) problems.push('no collections found');

if (problems.length > 0) {
  console.error(problems.join('\n'));
  process.exit(1);
}
console.log(`OK: ${collections.length} collections, ${environments.length} environment templates.`);
