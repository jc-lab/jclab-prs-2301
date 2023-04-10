import {
  firstSign, firstVerify, generateResignKey,
  PrivateKey, reSign, Signature1, verify
} from './index';

describe('proxy-re-signature test', function () {
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
        expect(s1.encode().length).toEqual(128);

        st = process.hrtime.bigint();
        verified = firstVerify(alice.getPublicKeyG1(), s1, message);
        totalVerifyFirst += (process.hrtime.bigint() - st);

        expect(verified).toBeTruthy();
        expect(firstVerify(alice.getPublicKeyG1(), s1, badMessage)).toBeFalsy();
        const s1Encoded = s1.encode();

        st = process.hrtime.bigint();
        const s2a = reSign(rk, s1);
        totalResign += (process.hrtime.bigint() - st);
        expect(s2a.encode().length).toEqual(192);

        st = process.hrtime.bigint();
        verified = verify(bob.getPublicKeyG1(), s2a, message);
        totalVerifySecond += (process.hrtime.bigint() - st);

        expect(verified).toBeTruthy();
        expect(verify(bob.getPublicKeyG1(), s2a, badMessage)).toBeFalsy();

        const s2b = reSign(rk, Signature1.decode(s1Encoded));
        expect(s2b.encode().length).toEqual(192);
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
    msg += `total sign = ${n} ms (${1000 / n} ops)\n`;
    n = Number(totalVerifyFirst / 100000n) / 10;
    msg += `total first verify = ${n} ms (${1000 / n} ops)\n`;
    n = Number(totalResign / 100000n) / 10;
    msg += `total resign = ${n} ms (${1000 / n} ops)\n`;
    n = Number(totalVerifySecond / 100000n) / 10;
    msg += `total second verify = ${n} ms (${1000 / n} ops)\n`;
    console.log(msg);
  });
});
