import { defineConfig } from 'tsup';

export default defineConfig({
  // Entry points - the main server file and worker
  entry: {
    index: 'server/index.ts',
    'codesign-worker': 'server/workers/codesign-worker.ts',
  },

  // Output directory
  outDir: 'dist',

  // Format: ES modules (matches package.json "type": "module")
  format: ['esm'],

  // Target Node.js environment
  target: 'node18',
  platform: 'node',

  // Generate source maps for debugging
  sourcemap: true,

  // Clean output directory before build
  clean: true,

  // Bundle dependencies
  bundle: true,

  // Split chunks for better code organization
  splitting: false,

  // Keep original file structure for easier debugging
  // This ensures server/index.ts -> dist/index.js
  // and imports work correctly
  outExtension({ format }) {
    return {
      js: '.js',
    };
  },

  // Don't minify in production to keep stack traces readable
  minify: false,

  // Keep original names for better debugging
  keepNames: true,

  // Skip type checking (tsc will do this)
  dts: false,

  // External packages that should not be bundled
  // Node built-ins are automatically external
  noExternal: [],

  // Shims for Node.js built-ins
  shims: true,

  // Handle .ts extensions in imports
  loader: {
    '.ts': 'ts',
  },

  // Preserve dynamic imports for worker threads
  treeshake: true,
});
