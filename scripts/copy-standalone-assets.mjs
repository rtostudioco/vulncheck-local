/**
 * VulnCheck Local — post-build step (cross-platform).
 *
 * Next.js `output: "standalone"` produces `.next/standalone/server.js`, but the
 * static assets and `public/` must be copied in manually. This replaces the
 * previous Unix-only `cp -r` chain so `npm run build` works on Windows, macOS
 * and Linux alike.
 */
import { cpSync, existsSync } from "node:fs";
import { join } from "node:path";

const root = process.cwd();
const standaloneDir = join(root, ".next", "standalone");

if (!existsSync(standaloneDir)) {
  console.error('✗ .next/standalone not found — run "next build" first.');
  process.exit(1);
}

cpSync(join(root, ".next", "static"), join(standaloneDir, ".next", "static"), {
  recursive: true,
});
cpSync(join(root, "public"), join(standaloneDir, "public"), {
  recursive: true,
});

console.log("✓ standalone assets copied (.next/static, public)");
