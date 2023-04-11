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

import {bls12_381} from '@noble/curves/bls12-381';
import {G1Encode, G2Encode} from './curve';

export type G1Point = typeof bls12_381.G1.ProjectivePoint.BASE
export type G2Point = typeof bls12_381.G2.ProjectivePoint.BASE

export class PrivateKey {
  private readonly _value: Uint8Array;
  private readonly _scalar: bigint;

  constructor(value: Uint8Array) {
    this._value = value;
    this._scalar = bls12_381.G1.normPrivateKeyToScalar(value);
  }

  public getBytes(): Uint8Array {
    return this._value;
  }

  public getScalar(): bigint {
    return this._scalar;
  }

  public getPublicKeyG1(): G1Point {
    return bls12_381.G1.ProjectivePoint.fromPrivateKey(this._value);
  }

  public getEncodedPublicKeyG1(): Uint8Array {
    const temp = this.getPublicKeyG1();
    return G1Encode(temp);
  }

  public getPublicKeyG2(): G2Point {
    return bls12_381.G2.ProjectivePoint.fromPrivateKey(this._value);
  }

  public getEncodedPublicKeyG2(): Uint8Array {
    const temp = this.getPublicKeyG2();
    return G2Encode(temp);
  }

  static fromBytes(input: Uint8Array): PrivateKey {
    return new PrivateKey(input);
  }

  static fromScalar(scalar: bigint): PrivateKey {
    return new PrivateKey(bls12_381.Fr.toBytes(scalar));
  }

  static generate(): PrivateKey {
    return new PrivateKey(bls12_381.utils.randomPrivateKey());
  }
}
