export const privateEndpointURLs = [
  "https://10.0.0.1/endpoint",
  "https://169.254.169.254/endpoint",
  "https://100.64.0.1/endpoint",
  "https://192.0.2.1/endpoint",
  "https://metadata.google.internal./endpoint",
  "https://[fc00::1]/endpoint",
  "https://[::ffff:10.0.0.1]/endpoint",
  "https://[2001:db8::1]/endpoint",
];
export function privateEndpointError(field: string, value: string) {
  const url = new URL(value);
  return {
    code: "discovery_private_host",
    message: `The ${field} URL (${url.toString()}) is not publicly routable: ${url.hostname}. If this is an internal IdP, add its origin to trustedOrigins.`,
  };
}
