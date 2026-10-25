# Package Installation and Distribution Smoke Harness

## User Value

Demonstrate that AuthScope's CLI can be packaged, distributed, and executed outside of its source checkout directory, identifying missing runtime artifacts, unbundled dependencies, or packaging configuration flaws before public distribution.

## Scope and Architecture

The distribution smoke testing harness ensures that `@soraforge/soroban-authscope` meets production packaging standards while preserving strict offline safety and secret isolation:

1. **Package Metadata Audit (`package.json`)**:
   - Enforces ESM module definition (`"type": "module"`).
   - Enforces the Node 22 engine boundary (`"engines": { "node": ">=22" }`).
   - Verifies explicit licensing metadata (`"license": "Apache-2.0"`).
   - Validates the binary entry point mapping (`"bin": { "authscope": "./dist/cli.js" }`).

2. **Executable CLI Shebang**:
   - Confirms that the CLI entry point starts with `#!/usr/bin/env node` so it can be directly invoked when linked or installed globally.

3. **Manifest and Secret Exclusion Audit**:
   - Audits npm pack manifests and tarball contents to ensure sensitive files are excluded:
     - Environment variables (`.env`, `.env.*`)
     - Private keys and certificates (`*.key`, `*.pem`, `id_rsa`)
     - Developer credentials and package publishing tokens (`.npmrc`)
     - Private captured RPC fixtures and unreviewed transaction records
     - Repository and VCS metadata (`.git/`)

4. **External Execution Verification**:
   - Verifies CLI execution outside the source directory root:
     - Standard help (`--help`) and version (`--version`) flags exit with code `0`.
     - Inspection of valid simulation input (`authscope inspect <file>`) returns code `0`.
     - Scope comparison between identical inputs (`authscope diff <file> <file>`) returns code `0`.
     - Malformed inputs return code `2` with clean, sanitized standard error output.

## Running the Smoke Harness

### Dry-run Manifest and Metadata Audit
Run the standalone smoke harness:
```bash
node tools/package-smoke/run.mjs
```

### Automated Unit and Integration Tests
Execute the deterministic distribution tests:
```bash
node --test tests/package-smoke.test.mjs
```

### Temporary Isolated Tarball Smoke Test
To test packaging into a throwaway sandbox directory without modifying root package settings:
```bash
# 1. Build TypeScript distribution files
npm run build

# 2. Package into a local tarball
npm pack

# 3. In a separate throwaway directory, install with lifecycle scripts disabled
DIR=$(mktemp -d)
cd "$DIR"
npm init -y
npm install --ignore-scripts /path/to/soraforge-soroban-authscope-0.1.0.tgz

# 4. Execute installed CLI outside repo
npx authscope --help
npx authscope --version

# 5. Clean up
rm -rf "$DIR"
```

## Security and Privacy Limitations

- **Offline by Default**: All packaging and smoke audits execute strictly offline without external network requests, RPC calls, or keypair generation.
- **No Private Package Modification**: The root `package.json` retains `"private": true` unless explicitly authorized by maintainers.
- **Scope Verification**: Successful CLI packaging demonstrates artifact completeness and execution integrity, but scope differences or exit codes do not evaluate smart contract vulnerability or cryptographic safety.
