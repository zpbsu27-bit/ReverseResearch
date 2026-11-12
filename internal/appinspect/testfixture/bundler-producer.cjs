// Verification producer only. Dependencies live in the supplied temporary root;
// RR never loads these packages or executes the generated bundle.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { createRequire } = require('node:module');
const [stage, destination] = process.argv.slice(2).map(p => path.resolve(p));
const producerRequire = createRequire(path.join(stage, 'producer', 'package.json'));
const webpack = producerRequire('webpack');
const esbuild = producerRequire('esbuild');
const sha = b => crypto.createHash('sha256').update(b).digest('hex');

(async () => {
  const work = path.join(stage, 'inputs');
  fs.mkdirSync(work, { recursive: true });
  fs.mkdirSync(destination, { recursive: true });
  const inputs = {
    'main.cjs': 'module.exports = require("./a.cjs");\n',
    'a.cjs': 'exports.answer = require("./dep.cjs").value;\n',
    'dep.cjs': 'exports.value = 42;\n',
  };
  for (const [name, value] of Object.entries(inputs)) fs.writeFileSync(path.join(work, name), value);
  const compiler = webpack({ mode: 'none', context: work, entry: './main.cjs', target: 'node',
    output: { path: destination, filename: 'webpack.cjs', library: { type: 'commonjs2' } },
    optimization: { minimize: false, concatenateModules: false }, devtool: false });
  const stats = await new Promise((resolve, reject) => compiler.run((err, result) => err ? reject(err) : resolve(result)));
  await new Promise((resolve, reject) => compiler.close(err => err ? reject(err) : resolve()));
  if (stats.hasErrors()) throw new Error(JSON.stringify(stats.toJson({ all: false, errors: true })));
  const ids = {};
  for (const module of stats.compilation.modules) if (module.resource && path.dirname(module.resource) === work) ids[path.basename(module.resource)] = String(stats.compilation.chunkGraph.getModuleId(module));
  await esbuild.build({ absWorkingDir: work, entryPoints: ['main.cjs'], bundle: true, platform: 'node', format: 'cjs',
    outfile: path.join(destination, 'esbuild.cjs'), sourcemap: false, legalComments: 'none', logLevel: 'silent' });
  const outputs = {};
  for (const name of ['webpack.cjs', 'esbuild.cjs']) { const data = fs.readFileSync(path.join(destination, name)); outputs[name] = { bytes: data.length, sha256: sha(data) }; }
  const receipt = { schema: 'rr-bundler-producer.v1', targetExecuted: false,
    webpackVersion: webpack.version, esbuildVersion: esbuild.version,
    webpackModuleIds: ids, inputs: Object.fromEntries(Object.entries(inputs).map(([name, value]) => [name, { source: value, sha256: sha(value) }])), outputs };
  fs.writeFileSync(path.join(destination, 'producer.json'), JSON.stringify(receipt, null, 2) + '\n');
  console.log(JSON.stringify(receipt));
})().catch(error => { console.error(error.message); process.exitCode = 1; });
