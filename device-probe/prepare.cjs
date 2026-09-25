// Prepare a private build of a temporary feature module for an existing debug app.
// Signing material is read from the host project and never copied into this repo.
const fs = require('node:fs');
const path = require('node:path');
const [host, output] = process.argv.slice(2);
const studio = process.env.DEVECO_STUDIO || '/Applications/DevEco-Studio.app/Contents';
const json5 = require(path.join(studio, 'tools/hvigor/hvigor-ohos-plugin/node_modules/json5'));
if (!host || !output || fs.existsSync(output)) {
  throw new Error('usage: node prepare.cjs HOST_PROJECT NEW_PRIVATE_BUILD_DIRECTORY');
}
const profile = json5.parse(fs.readFileSync(path.join(host, 'build-profile.json5'), 'utf8'));
const product = profile.app.products.find(p => p.name === 'default');
const signing = profile.app.signingConfigs.find(s => s.name === product.signingConfig);
if (!signing) throw new Error('host project has no default signing configuration');
fs.mkdirSync(output, { recursive: true, mode: 0o700 });
function json(name, value) {
  const dest = path.join(output, name);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, JSON.stringify(value, null, 2), { mode: 0o600 });
}
fs.cpSync(path.join(host, 'AppScope'), path.join(output, 'AppScope'), { recursive: true });
fs.cpSync(path.join(__dirname, 'src'), path.join(output, 'hap_probe/src'), { recursive: true });
json('build-profile.json5', {
  app: { signingConfigs: [signing], products: [product], buildModeSet: [{ name: 'debug' }] },
  modules: [{ name: 'hap_probe', srcPath: './hap_probe', targets: [{ name: 'default', applyToProducts: ['default'] }] }]
});
json('oh-package.json5', { name: 'hap-device-probe', version: '0.0.1', modelVersion: '6.0.0', dependencies: {} });
json('hvigor/hvigor-config.json5', { modelVersion: '6.0.0', dependencies: {} });
json('hap_probe/oh-package.json5', { name: 'hap_probe', version: '0.0.1', dependencies: {} });
json('hap_probe/build-profile.json5', { apiType: 'stageMode', targets: [{ name: 'default' }] });
fs.writeFileSync(path.join(output, 'hvigorfile.ts'), "import { appTasks } from '@ohos/hvigor-ohos-plugin';\nexport default { system: appTasks };\n");
fs.writeFileSync(path.join(output, 'hap_probe/hvigorfile.ts'), "import { hapTasks } from '@ohos/hvigor-ohos-plugin';\nexport default { system: hapTasks };\n");
fs.writeFileSync(path.join(output, 'local.properties'), `sdk.dir=${studio}/sdk\n`);
console.log(`Prepared temporary feature module in ${output}`);
