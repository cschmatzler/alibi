export function customSPMetadata(baseURL: string, providerId: string) {
  return {
    entityID: "https://sp.example.test/unused",
    metadata: `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.test/from-xml"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAssertionsSigned="true" AuthnRequestsSigned="false"><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat><md:AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${baseURL}/api/auth/sso/saml2/sp/acs/${providerId}"/></md:SPSSODescriptor></md:EntityDescriptor>`,
  };
}
