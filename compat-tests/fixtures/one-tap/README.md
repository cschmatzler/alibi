These generated RSA keys are public test credentials for the local Google
One Tap oracle. They authenticate fixture identities only. The SDK signs real
RS256 credentials with the first key; the second key supplies a wrong-signature
control with the same key ID. Both servers fetch the first public JWKS from a
local provider transport and perform their ordinary verification logic.
