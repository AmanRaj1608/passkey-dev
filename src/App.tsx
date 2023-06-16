import React, { useState } from "react";
import {
  browserSupportsWebAuthn,
  browserSupportsWebAuthnAutofill,
  platformAuthenticatorIsAvailable,
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";
// @ts-ignore
import elliptic from "elliptic";
import base64url from "base64url";
import { v4 as uuidv4 } from "uuid";
import { AsnParser } from "@peculiar/asn1-schema";
import { ECDSASigValue } from "@peculiar/asn1-ecc";
import { utils } from "@passwordless-id/webauthn";
import * as cbor from "./utils/cbor";
import {
  parseAuthData,
  publicKeyCredentialToJSON,
  shouldRemoveLeadingZero,
} from "./utils/helpers";
import entryPointAbi from "./utils/abi.json";
import { ethers, BigNumber } from "ethers";
const EC = elliptic.ec;
const ec = new EC("p256");

export enum COSEKEYS {
  kty = 1,
  alg = 3,
  crv = -1,
  x = -2,
  y = -3,
  n = -1,
  e = -2,
}

const App: React.FC = () => {
  const [credentials, setCredentials] = useState<any>(null);
  const [publicKeys, setPublicKeys] = useState([] as any[]);

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

    const platform = platformAuthenticatorAvailable
      ? "platform"
      : "cross-platform";

    const username = "test";
    const challenge = uuidv4();
    // const challenge = "";
    const obj = {
      rp: {
        name: window.location.hostname,
        id: window.location.hostname,
      },
      user: {
        id: username,
        name: username,
        displayName: username,
      },
      challenge: challenge,
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      attestation: "direct",
      // timeout: 60000,
      authenticatorSelection: {
        userVerification: "required", // Webauthn default is "preferred"
        authenticatorAttachment: platform,
      },
    };
    console.log("registration options", obj);
    const publicKeyCredential = await startRegistration(obj as any);
    console.log(publicKeyCredential);

    const attestationObject = base64url.toBuffer(
      publicKeyCredential.response.attestationObject
    );
    const authData = cbor.decode(attestationObject.buffer, undefined, undefined)
      .authData as Uint8Array;

    let authDataParsed = parseAuthData(authData);

    let pubk = cbor.decode(
      authDataParsed.COSEPublicKey.buffer,
      undefined,
      undefined
    );

    const x = pubk[COSEKEYS.x];
    const y = pubk[COSEKEYS.y];

    const pk = ec.keyFromPublic({ x, y });

    const publicKey = [
      "0x" + pk.getPublic("hex").slice(2, 66),
      "0x" + pk.getPublic("hex").slice(-64),
    ];
    console.log({ publicKey });
    setCredentials(publicKeyCredential);
    setPublicKeys(publicKey);
  };

  const getMessageSignature = (authResponseSignature: string): BigNumber[] => {
    // See https://github.dev/MasterKale/SimpleWebAuthn/blob/master/packages/server/src/helpers/iso/isoCrypto/verifyEC2.ts
    // for extraction of the r and s bytes from the raw signature buffer
    const parsedSignature = AsnParser.parse(
      base64url.toBuffer(authResponseSignature),
      ECDSASigValue
    );
    let rBytes = new Uint8Array(parsedSignature.r);
    let sBytes = new Uint8Array(parsedSignature.s);
    if (shouldRemoveLeadingZero(rBytes)) {
      rBytes = rBytes.slice(1);
    }
    if (shouldRemoveLeadingZero(sBytes)) {
      sBytes = sBytes.slice(1);
    }
    // r and s values
    return [BigNumber.from(rBytes), BigNumber.from(sBytes)];
  };

  const signUserOperationHash = async (userOpHash: string) => {
    const challenge = utils
      .toBase64url(ethers.utils.arrayify(userOpHash))
      .replace(/=/g, "");
    const authData = await startAuthentication({
      rpId: window.location.hostname,
      challenge: challenge,
      userVerification: "required",
      // authenticatorType: "both",
      allowCredentials: [
        {
          type: "public-key",
          id: credentials.rawId,
        },
      ],
      // timeout: 60000,
    });
    const sign = getMessageSignature(authData.response.signature);
    console.log({ challenge, sign, authData });
    const clientDataJSON = new TextDecoder().decode(
      utils.parseBase64url(authData.response.clientDataJSON)
    );
    const challengePos = clientDataJSON.indexOf(challenge);
    const challengePrefix = clientDataJSON.substring(0, challengePos);
    const challengeSuffix = clientDataJSON.substring(
      challengePos + challenge.length
    );
    const authenticatorData = new Uint8Array(
      utils.parseBase64url(authData.response.authenticatorData)
    );
    const sig = {
      id: BigNumber.from(
        ethers.utils.keccak256(new TextEncoder().encode(credentials.id))
      ),
      r: sign[0],
      s: sign[1],
      authData: authenticatorData,
      clientDataPrefix: challengePrefix,
      clientDataSuffix: challengeSuffix,
    };
    console.log({ sig });
    let encodedSig = ethers.utils.defaultAbiCoder.encode(
      ["bytes32", "uint256", "uint256", "bytes", "string", "string"],
      [
        sig.id,
        sig.r,
        sig.s,
        sig.authData,
        sig.clientDataPrefix,
        sig.clientDataSuffix,
      ]
    );
    console.log({ encodedSig });
    return encodedSig;
  };

  const signUserOperation = async () => {
    const entryPointAddress = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789";
    const userOp = {
      sender: "0x8Ef446eE7EEd11Eb4d997C7dA1A891E96bfa1f9a",
      nonce: "0x00",
      initCode: "0x",
      callData:
        "0x9e5d4c490000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc0000000000000000000000000000000000000000000000000de0b6b3a764000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000",
      paymasterAndData: "0x",
      maxFeePerGas: 1148045680,
      maxPriorityFeePerGas: 1000000000,
      callGasLimit: 39580,
      verificationGasLimit: 150000,
      preVerificationGas: 21000,
      signature:
        "0x47c166ca1098d73e502281d09a65732a77a4f88af02d07564b59f30261a48bfd607c7d92d1d434f325a72e5523655c18cfa804ab54a6ac68f6ed161ba41cbe9d1b",
    };
    const provider = new ethers.providers.JsonRpcProvider(
      "https://mainnet.infura.io/v3/8af40d61a66047ca8294a0bb43b958fa"
    );
    const entryPoint = new ethers.Contract(
      entryPointAddress,
      entryPointAbi,
      provider
    );
    const userOpHash = await entryPoint.getUserOpHash(userOp);
    const signature = await signUserOperationHash(userOpHash);
    console.log({ userOpHash, signature });
    return signature;
  };

  const verifyPassKey = async () => {
    const challenge = "";
    const response = await startAuthentication({
      rpId: window.location.hostname,
      challenge: challenge,
      allowCredentials: [
        {
          type: "public-key",
          id: credentials.rawId,
        },
      ],
      // timeout: 60000,
    });
    console.log(response);
    const publicKeyCredentialParsed = publicKeyCredentialToJSON(response);

    const parsedSignature = AsnParser.parse(
      base64url.toBuffer(publicKeyCredentialParsed.response.signature),
      ECDSASigValue
    );

    let rBytes = new Uint8Array(parsedSignature.r);
    let sBytes = new Uint8Array(parsedSignature.s);

    if (shouldRemoveLeadingZero(rBytes)) {
      rBytes = rBytes.slice(1);
    }

    if (shouldRemoveLeadingZero(sBytes)) {
      sBytes = sBytes.slice(1);
    }

    const signature = [
      "0x" + Buffer.from(rBytes).toString("hex"),
      "0x" + Buffer.from(sBytes).toString("hex"),
    ];
    console.log({ signature });
  };

  return (
    <div>
      <main>
        <h2>Biconomy Passkeys 256k1 signature test</h2>
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 15,
            maxWidth: 200,
            margin: "0 auto",
          }}
        >
          <button onClick={createPassKey}>Create Passkey</button>
          <button onClick={signUserOperation}>Verify Passkey</button>
        </div>
      </main>
    </div>
  );
};

export default App;
