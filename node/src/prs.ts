/*******************************************************************************
 * Copyright 2022 jc-lab (joseph@jc-lab.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/

import * as crypto from 'crypto';
import { bls12_381 } from '@noble/curves/bls12-381';
import { sha256 } from '@noble/hashes/sha256';
import {
  G1Point,
  G2Point,
  PrivateKey
} from './key';
import {G2Decode, G2Encode} from './curve';

const z = bls12_381.pairing(bls12_381.G1.ProjectivePoint.BASE, bls12_381.G2.ProjectivePoint.BASE, true);

function hashFr(a: Uint8Array): bigint {
  const hash = sha256.create();
  hash.update(a);
  return bls12_381.Fr.create(bls12_381.Fr.fromBytes(hash.digest()));
}

export class Signature1 {
  public readonly r: G2Point;
  public readonly s: bigint;

  constructor(r: G2Point, s: bigint) {
    this.r = r;
    this.s = s;
  }

  public encode(): Uint8Array {
    return Buffer.concat([G2Encode(this.r), bls12_381.Fr.toBytes(this.s)]);
  }

  static decode(input: Uint8Array): Signature1 {
    const r = input.slice(0, 97);
    const s = input.slice(97);
    return new Signature1(G2Decode(r), bls12_381.Fr.fromBytes(s));
  }
}

export class Signature2 {
  public readonly r: G2Point;
  public readonly s: G2Point;

  constructor(r: typeof bls12_381.G2.ProjectivePoint.BASE, s: typeof bls12_381.G2.ProjectivePoint.BASE) {
    this.r = r;
    this.s = s;
  }

  public encode(): Uint8Array {
    return Buffer.concat([G2Encode(this.r), G2Encode(this.s)]);
  }

  static decode(input: Uint8Array): Signature2 {
    const r = input.slice(0, 97);
    const s = input.slice(97);
    return new Signature2(G2Decode(r), G2Decode(s));
  }
}

export function generateResignKey(senderPublicKey: G2Point, privateKey: bigint | PrivateKey): G2Point {
  let privateKeyScalar: bigint;
  if (typeof privateKey === 'bigint') {
    privateKeyScalar = privateKey;
  } else {
    privateKeyScalar = privateKey.getScalar();
  }
  return senderPublicKey.multiply(bls12_381.Fr.inv(privateKeyScalar));
}

export function firstSign(privKey: PrivateKey, message: Uint8Array): Signature1 {
  const k = bls12_381.Fr.create(bls12_381.Fr.fromBytes(crypto.randomBytes(32)));
  const h = hashFr(message);
  const rQ = bls12_381.G2.ProjectivePoint.BASE.multiply(k);
  const s = bls12_381.Fr.mul(bls12_381.Fr.inv(privKey.getScalar()), bls12_381.Fr.add(k, h));
  return new Signature1(rQ, s);
}

export function reSign(resignKey: G2Point, signature: Signature1): Signature2 {
  const s = resignKey.multiply(signature.s);
  return new Signature2(signature.r, s);
}

export function firstVerify(publicKey: G1Point, signature: Signature1, message: Uint8Array): boolean {
  const h = hashFr(message);
  const g2s = bls12_381.G2.ProjectivePoint.BASE.multiply(signature.s);
  const v1 = bls12_381.pairing(publicKey, g2s, true); // z^(k + h)
  const v2_a = bls12_381.Fp12.pow(z, h); // z^h
  const v2_b = bls12_381.pairing(bls12_381.G1.ProjectivePoint.BASE, signature.r, true); // z^k
  const v2 = bls12_381.Fp12.mul(v2_a, v2_b);
  return bls12_381.Fp12.eql(v1, v2);
}

export function verify(publicKey: G1Point, signature: Signature2, message: Uint8Array): boolean {
  const h = hashFr(message);
  const v1 = bls12_381.pairing(publicKey, signature.s, true);
  const v2_a = bls12_381.Fp12.pow(z, h); // z^h
  const v2_b = bls12_381.pairing(bls12_381.G1.ProjectivePoint.BASE, signature.r, true); // z^k
  const v2 = bls12_381.Fp12.mul(v2_a, v2_b);
  return bls12_381.Fp12.eql(v1, v2);
}
