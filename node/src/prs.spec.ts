import {
  firstSign, firstVerify, G2Decode, generateResignKey,
  PrivateKey, reSign, Signature1, verify
} from './index';
import {G2Encode} from './curve';

describe('proxy-re-signature test', function () {
  it('reproducible case', () => {
    const message = Buffer.from('hello world');

    const alice = PrivateKey.fromBytes(Buffer.from('1282a07a980e79ac66b81c6c9f22cf3544fac7f7ddc473e178646d58a88c0c4f', 'hex'));
    const bob = PrivateKey.fromBytes(Buffer.from('341340255f876d1c446080f77ff44ec0518014776cd292df2901a63dd6df7f53', 'hex'));
    const rk = generateResignKey(alice.getPublicKeyG2(), bob.getScalar());

    expect(Buffer.from(alice.getBytes()).toString('hex')).toEqual('1282a07a980e79ac66b81c6c9f22cf3544fac7f7ddc473e178646d58a88c0c4f');
    expect(Buffer.from(alice.getEncodedPublicKeyG1()).toString('hex')).toEqual('0213fa33245c2b8155804330a84f065895830395df57b47887788d82d6ec82dbc0fdabcd3dd9f0fd7aa3bf9b68be3605df');
    expect(Buffer.from(alice.getEncodedPublicKeyG2()).toString('hex')).toEqual('03026be1458932fb271f53ae9c41eacbbd739362d8ac2fba3d32d7c0935f186a55bed16661491d38493e466e321f4a97f00cd982e56976360d8fd03516658b6262ff1bf8c7d9a7b1d5478da438769d37fb53ac50f63477ead0216f1d78b4f8a889');

    expect(Buffer.from(bob.getBytes()).toString('hex')).toEqual('341340255f876d1c446080f77ff44ec0518014776cd292df2901a63dd6df7f53');
    expect(Buffer.from(bob.getEncodedPublicKeyG1()).toString('hex')).toEqual('0306d5b0d11004f2b12f9beac4fb5b02e671ba96bb638af174a55bc1904c62b05588a7e2bc37c1a123075f8308c463c391');
    expect(Buffer.from(bob.getEncodedPublicKeyG2()).toString('hex')).toEqual('0300c54b72b75ea321b54e072d122338d019710e57dd30234bcc3624dffb4be75b4a1adecc924aada34f655f8c33147fff0790ad1ae160196688c2cf4fe3e7a82d578d00e1bf3da77c85d91f793203d6778eb9957000c2a1469d5a04504e53fd7f');

    const rkEncoded = G2Encode(rk);
    expect(Buffer.from(rkEncoded).toString('hex')).toEqual('030ac31b09847297f28cadb0fe88707553e7e9e041010c3d1ad3067c601506f4819f55da80bcd84cecc7508d73d9b89f0215464449b04275fa35752d6a3f8c571228371683004c0b164045b7b460c90db0b88387b895c80fa2e010af8ab5aecced');
    const rkDecoded = G2Decode(rkEncoded);
    expect(rkDecoded.toHex(true)).toEqual(rk.toHex(true));

    const s1 = Signature1.decode(Buffer.from('0209e3164cfe2b5dd8839d0a12d2ddc2b48c9402d103a021163c547d7099ab7d08bd74980c8d330ab0532bc93d6485815a00604536cf702d563c3b1fcd7efba451edcfd67376fed216f4c6994cd01063a817730eae7af863956482817b11f5372607b5cf944cf636cfb4f681d508aa4b01a66fe11f8f1115a9ed6b1c3656c2bab3', 'hex'));
    const verified = firstVerify(alice.getPublicKeyG1(), s1, message);
    expect(verified).toBeTruthy();

    const s2 = reSign(rk, s1);
    expect(Buffer.from(s2.encode()).toString('hex')).toEqual('0209e3164cfe2b5dd8839d0a12d2ddc2b48c9402d103a021163c547d7099ab7d08bd74980c8d330ab0532bc93d6485815a00604536cf702d563c3b1fcd7efba451edcfd67376fed216f4c6994cd01063a817730eae7af863956482817b11f53726030f8e48a513cac737e946f24216838afccb66161550f19e44a277c23091305cb6d75141da53d9de8174eff03da2d52d0a016a84720065856163b97b8014ced93b691528c4e52e7da2ed1c98c29925cedd9658f4a1b5412bea35ab97de2d10ace4');

    expect(verify(bob.getPublicKeyG1(), s2, message)).toBeTruthy();
  });

  it('randomly', () => {
    const iteration = 5;

    const message = Buffer.from('hello world');
    const badMessage = Buffer.from('x');

    let totalSign = 0n;
    let totalVerifyFirst = 0n;
    let totalResign = 0n;
    let totalVerifySecond = 0n;

    for (let i=0; i<iteration; i++) {
      let st: bigint;
      const alice = PrivateKey.generate();
      const bob = PrivateKey.generate();
      const rk = generateResignKey(alice.getPublicKeyG2(), bob.getScalar());

      for (let j=0; j<2; j++) {
        let verified: boolean;

        st = process.hrtime.bigint();
        const s1 = firstSign(alice, message);
        totalSign += (process.hrtime.bigint() - st);
        expect(s1.encode().length).toEqual(129);

        st = process.hrtime.bigint();
        verified = firstVerify(alice.getPublicKeyG1(), s1, message);
        totalVerifyFirst += (process.hrtime.bigint() - st);

        expect(verified).toBeTruthy();
        expect(firstVerify(alice.getPublicKeyG1(), s1, badMessage)).toBeFalsy();
        const s1Encoded = s1.encode();

        st = process.hrtime.bigint();
        const s2a = reSign(rk, s1);
        totalResign += (process.hrtime.bigint() - st);
        expect(s2a.encode().length).toEqual(194);

        st = process.hrtime.bigint();
        verified = verify(bob.getPublicKeyG1(), s2a, message);
        totalVerifySecond += (process.hrtime.bigint() - st);

        expect(verified).toBeTruthy();
        expect(verify(bob.getPublicKeyG1(), s2a, badMessage)).toBeFalsy();

        const s2b = reSign(rk, Signature1.decode(s1Encoded));
        expect(s2b.encode().length).toEqual(194);
        expect(verify(bob.getPublicKeyG1(), s2b, message)).toBeTruthy();
        expect(verify(bob.getPublicKeyG1(), s2b, badMessage)).toBeFalsy();
      }
    }

    let n: number;
    let msg: string = `iterations = ${iteration}\n`;

    totalSign /= BigInt(iteration);
    totalVerifyFirst /= BigInt(iteration);
    totalResign /= BigInt(iteration);
    totalVerifySecond /= BigInt(iteration);

    n = Number(totalSign / 100000n) / 10;
    msg += `total sign = ${n} ms (${1000 / n} op/s)\n`;
    n = Number(totalVerifyFirst / 100000n) / 10;
    msg += `total first verify = ${n} ms (${1000 / n} op/s)\n`;
    n = Number(totalResign / 100000n) / 10;
    msg += `total resign = ${n} ms (${1000 / n} op/s)\n`;
    n = Number(totalVerifySecond / 100000n) / 10;
    msg += `total second verify = ${n} ms (${1000 / n} op/s)\n`;
    console.log(msg);
  });
});
