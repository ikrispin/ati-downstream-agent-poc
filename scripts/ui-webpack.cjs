// Keep the upstream HCC configuration and supply this experiment's certificate.
const fs = require('node:fs');
const path = require('node:path');

const labRoot = path.resolve(__dirname, '..');
const uiRoot = path.join(labRoot, '.local/platform/ui');
const config = require(path.join(
  uiRoot,
  'node_modules/@redhat-cloud-services/frontend-components-config/bin/dev.webpack.config.js',
));
const tlsRoot = path.join(labRoot, '.local/state/ui-tls');
config.devServer.server = {
  type: 'https',
  options: {
    key: fs.readFileSync(path.join(tlsRoot, 'server.key')),
    cert: fs.readFileSync(path.join(tlsRoot, 'server.crt')),
  },
};
module.exports = config;
