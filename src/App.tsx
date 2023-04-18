import React from "react";
import {
  browserSupportsWebAuthn,
  browserSupportsWebAuthnAutofill,
  platformAuthenticatorIsAvailable,
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";

const App: React.FC = () => {
  const createPassKey = async () => {
    const supportsWebAuthn = browserSupportsWebAuthn();
    const supportsWebAuthnAutofill = await browserSupportsWebAuthnAutofill();
    const platformAuthenticatorAvailable =
      await platformAuthenticatorIsAvailable();

    console.log(
`Browser supports WebAuthn: ${supportsWebAuthn}
Browser supports WebAuthn Autofill: ${supportsWebAuthnAutofill}
Platform Authenticator available: ${platformAuthenticatorAvailable}`
    );

    const registration = await startRegistration({
      rp: {
        name: "SimpleWebAuthn",
        id: "https://passkey-dev.vercel.app",
      },
      user: {
        id: "1234567890",
        name: "aman",
        displayName: "Aman",
      },
      challenge: "MA==",
      pubKeyCredParams: [{ type: "public-key", alg: -257 }],
      // timeout: 60000,
      // attestation?: "direct",
    });
    console.log(registration);
  };

  return (
    <div>
      <main>
        <h2>WebAuthn Passkeys spec256k1 test</h2>
        <button onClick={createPassKey}>Create Passkey</button>
      </main>
    </div>
  );
};

export default App;
