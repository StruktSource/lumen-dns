import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const context = { console };
context.window = context;
context.document = {
  createElement() { throw new Error('core.js created DOM while loading'); },
  querySelector() { return null; }
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(new URL('../js/core.js', import.meta.url), 'utf8'), context, { filename: 'core.js' });

const config = {
  metrics: null,
  listen: { certificate: null, private_key: null },
  web: { certificate: null, private_key: null },
  filtering: { default_profile: null, lists: [], action: { kind: 'refused' } },
  resolver: { root_hints: null, trust_anchor: null, upstream_ca: null, providers: [], mode: 'recursive', strategy: null },
  zones: [
    {
      name: 'home.arpa',
      managed: {
        description: null,
        default_ttl: 300,
        records: [{
          name: '_443._tcp.router',
          ttl: null,
          type: 'tlsa',
          usage: 3,
          selector: 1,
          matching_type: 1,
          certificate_association_data: 'A1B2C3D4'
        }]
      }
    },
    { name: 'advanced.arpa', text: '$ORIGIN advanced.arpa.\n' }
  ]
};

const normalized = context.L.normalizeConfig(config);
assert.equal(normalized.zones[0].managed.description, '');
assert.deepEqual(JSON.parse(JSON.stringify(context.L.toServer(normalized).config)), config);
