'use strict';
const fs = require('node:fs');
const path = require('node:path');
const target = path.join(process.argv[2], 'tunnel', 'tunnel.go');
const source = fs.readFileSync(target, 'utf8').replace(/\r\n/g, '\n');
const start = source.indexOf('func handleTCPConn(connCtx C.ConnContext) {');
const end = source.indexOf('func logMetadataErr(', start);
if (start < 0 || end <= start) throw new Error('Unexpected pinned TCP handler');
let handler = source.slice(start, end);
function replaceOnce(before, after) {
  if (handler.split(before).length !== 2) throw new Error('Unexpected pinned TCP handler layout');
  handler = handler.replace(before, () => after);
}
replaceOnce('\tmetadata := connCtx.Metadata()\n', '\tmetadata := connCtx.Metadata()\n\tif netVergeStartupBlocked(metadata) { return }\n');
replaceOnce('\tvar peekBytes []byte\n\tvar peekLen int', '\tvar peekBytes []byte\n\tvar peekLen int\n\tnvCandidate := netVergeRouteCandidate(metadata)\n\tvar nvHandoff *netVergeRouteConfig');
replaceOnce('\t\tif N.NeedHandshake(remoteConn) {', '\t\t// Decide using the actual successful dial, before native first-write.\n\t\tif nvCandidate != nil && netVergeRouteAdmit(proxy, remoteConn) {\n\t\t\tnvHandoff = nvCandidate\n\t\t\treturn\n\t\t}\n\n\t\tif N.NeedHandshake(remoteConn) {');
replaceOnce('\t_ = conn.SetReadDeadline(time.Time{}) // reset\n\thandleSocket(conn, remoteConn)', '\t_ = conn.SetReadDeadline(time.Time{}) // reset\n\tif nvHandoff != nil {\n\t\t// The buffered inbound still contains the original first bytes.\n\t\t// The tracker wraps the original outbound; do not unwrap or retry.\n\t\tif err := nvHandoff.handle(conn, remoteConn, metadata.Clone(), rule); err != nil {\n\t\t\tlog.Warnln("[NetVerge MITM] original connection handoff failed")\n\t\t}\n\t\treturn\n\t}\n\thandleSocket(conn, remoteConn)');
fs.writeFileSync(target, source.slice(0,start)+handler+source.slice(end));
