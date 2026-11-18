import * as esbuild from 'esbuild'

await esbuild.build({
  entryPoints: ['public/client.js'],
  bundle: true,
  format: 'esm',
  platform: 'browser',
  outfile: 'public/client.bundle.js'
})
