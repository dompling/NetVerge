'use strict';

// Test-only instrumentation of the exact pinned upstream source. Never
// included in a packaged engine. Fail closed if upstream changes shape.
const fs = require('node:fs');
const path = require('node:path');
const target = path.join(process.argv[2], 'adapter', 'outbound', 'base.go');
let source = fs.readFileSync(target, 'utf8').replace(/\r\n/g, '\n');
function replaceOnce(before, after) {
  if (source.split(before).length !== 2) throw new Error('Unexpected upstream adapter connection layout');
  source = source.replace(before, after);
}
replaceOnce('type conn struct {\n\tN.ExtendedConn\n\tchain       C.Chain\n\tpdChain     C.Chain\n\tadapterAddr string\n}', 'type conn struct {\n\tN.ExtendedConn\n\tchain       C.Chain\n\tpdChain     C.Chain\n\tadapterAddr string\n\tnetVergeLabTypes []C.AdapterType\n}');
replaceOnce('func (c *conn) AppendToChains(a C.ProxyAdapter) {\n\tc.chain = append(c.chain, a.Name())', 'func (c *conn) AppendToChains(a C.ProxyAdapter) {\n\tc.netVergeLabTypes = append(c.netVergeLabTypes, a.Type())\n\tc.chain = append(c.chain, a.Name())');
replaceOnce('func (c *conn) Upstream() any {', '// NetVergeLabAdapterTypes records the actual dial path, not group predictions.\nfunc (c *conn) NetVergeLabAdapterTypes() []C.AdapterType {\n\treturn append([]C.AdapterType(nil), c.netVergeLabTypes...)\n}\n\nfunc (c *conn) Upstream() any {');
replaceOnce('cc := &conn{N.NewExtendedConn(c), nil, nil, a.Addr()}', 'cc := &conn{ExtendedConn: N.NewExtendedConn(c), adapterAddr: a.Addr()}');
fs.writeFileSync(target, source);
