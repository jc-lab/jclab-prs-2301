import {bls12_381} from '@noble/curves/bls12-381';
import {G1Point, G2Point} from './key';

export function G1Encode(point: G1Point): Uint8Array {
  const { x, y } = point.toAffine();
  const t = bls12_381.Fp.toBytes(x);
  const prefix = Buffer.alloc(1);

  // compressed
  prefix[0] = 0x02;
  if (bls12_381.Fp.isOdd!(y)) {
    prefix[0] = 0x03;
  }

  return Buffer.concat([prefix, t]);
}

export function G1Decode(bytes: Uint8Array): G1Point {
  const first = bytes[0];
  const isCompressedEven = first == 0x02;
  const isCompressedOdd = first == 0x03;

  if (isCompressedEven || isCompressedOdd) {
    const x = bls12_381.Fp.fromBytes(bytes.slice(1, 1 + bls12_381.Fp.BYTES));

    const right = bls12_381.Fp.add(bls12_381.Fp.pow(x, 3n), bls12_381.Fp.create(bls12_381.CURVE.G1.b)); // y² = x³ + b
    let y = bls12_381.Fp.sqrt(right);
    if (!y) throw new Error('Invalid compressed G1 point');

    if (isCompressedOdd != bls12_381.Fp.isOdd!(y)) {
      y = bls12_381.Fp.neg(y);
    }

    return new bls12_381.G1.ProjectivePoint(x, y, bls12_381.Fp.ONE);
  }
  throw new Error('invalid signature: ' + first.toString(16));
}

export function G2Encode(point: G2Point): Uint8Array {
  const { x, y } = point.toAffine();
  const x_0 = bls12_381.Fp.toBytes(x.c0);
  const x_1 = bls12_381.Fp.toBytes(x.c1);
  const prefix = Buffer.alloc(1);

  // compressed
  prefix[0] = 0x02;
  if (bls12_381.Fp2.isOdd!(y)) {
    prefix[0] = 0x03;
  }

  return Buffer.concat([prefix, x_1, x_0]);
}

export function G2Decode(bytes: Uint8Array): G2Point {
  const first = bytes[0];
  const isCompressedEven = first == 0x02;
  const isCompressedOdd = first == 0x03;

  const { b } = bls12_381.CURVE.G2;

  if (isCompressedEven || isCompressedOdd) {
    const x_1 = bls12_381.Fp.fromBytes(bytes.slice(1, 1 + bls12_381.Fp.BYTES));
    const x_0 = bls12_381.Fp.fromBytes(bytes.slice(1 + bls12_381.Fp.BYTES, 1 + bls12_381.Fp.BYTES * 2));
    const x = bls12_381.Fp2.create({c0: bls12_381.Fp.create(x_0), c1: bls12_381.Fp.create(x_1)});
    const right = bls12_381.Fp2.add(bls12_381.Fp2.pow(x, 3n), b); // y² = x³ + 4 * (u+1) = x³ + b
    let y = bls12_381.Fp2.sqrt(right);
    const yIsOdd = bls12_381.Fp2.isOdd!(y);
    if (isCompressedOdd != yIsOdd) {
      y = bls12_381.Fp2.neg(y);
    }
    return bls12_381.G2.ProjectivePoint.fromAffine({x, y});
  }
  throw new Error('invalid signature: ' + first.toString(16));
}
