import { createSocket } from "node:dgram";
import { setServers } from "node:dns/promises";

import packet from "dns-packet";
export async function ssoDnsFixture() {
  const server = createSocket("udp4");
  let records: string[][] = [];
  const queries: string[] = [];
  server.on("message", (bytes, peer) => {
    const query = packet.decode(bytes);
    const question = query.questions?.[0];
    if (!question) return;
    queries.push(question.name);
    const response = packet.encode({
      type: "response",
      id: query.id,
      flags: packet.RECURSION_AVAILABLE | packet.AUTHORITATIVE_ANSWER,
      questions: query.questions,
      answers: records.map((chunks) => ({
        name: question.name,
        type: "TXT",
        ttl: 0,
        data: chunks.map((chunk) => Buffer.from(chunk)),
      })),
    });
    server.send(response, peer.port, peer.address);
  });
  await new Promise<void>((resolve) => server.bind(0, "127.0.0.1", resolve));
  const address = server.address();
  if (typeof address === "string") throw new Error("Expected UDP address");
  setServers([`127.0.0.1:${address.port}`]);
  server.unref();
  return {
    setRecords(value: string[][]) {
      records = value;
    },
    queries() {
      return [...queries];
    },
  };
}
