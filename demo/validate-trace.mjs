#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const root = dirname(fileURLToPath(import.meta.url));
const schema = JSON.parse(readFileSync(join(root, 'trace.schema.json'), 'utf8'));
const lines = readFileSync(join(root, 'lifeline.trace.jsonl'), 'utf8').trim().split('\n');
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validate = ajv.compile(schema);
let failures = 0;
for (const [index, line] of lines.entries()) {
  const event = JSON.parse(line);
  if (!validate(event)) {
    failures += 1;
    console.error(`line ${index + 1}: ${ajv.errorsText(validate.errors, { separator: '\n  ' })}`);
  }
}
if (failures) throw new Error(`${failures} trace events failed schema validation`);
console.log(`${lines.length} trace events satisfy ${schema.$id}`);
