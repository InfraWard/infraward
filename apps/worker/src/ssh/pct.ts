import { expandQuery } from '@infraward/connectors';
import type { StreamingHostExec } from './ssh-client.js';

/**
 * Ejecución dentro de un CT desde su nodo: todo pasa por la consulta `pct-exec <vmid> <argv…>` del
 * ayudante de root del nodo. Dentro del CT ya se es root y no hay ayudante de InfraWard, así que
 * una consulta se ejecuta con su comando real (`expandQuery`, que la valida igual que el ayudante).
 */
export function throughPct(
  node: StreamingHostExec,
  vmid: number,
): StreamingHostExec {
  const inCt = (argv: string[]) => ({
    name: 'pct-exec' as const,
    args: [String(vmid), ...argv],
  });
  return {
    run: (argv) => node.query(inCt(argv)),
    query: async (query) => node.query(inCt(expandQuery(query))),
    streamToFile: async (query, dest, limits) =>
      node.streamToFile(inCt(expandQuery(query)), dest, limits),
    streamArgvToFile: (argv, dest, limits) =>
      node.streamToFile(inCt(argv), dest, limits),
  };
}
