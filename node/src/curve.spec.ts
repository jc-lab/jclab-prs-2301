import {
  G1Decode,
  G1Encode, G2Decode, G2Encode,
  PrivateKey
} from './index';

describe('Curve', function () {
  const sample = PrivateKey.fromBytes(Buffer.from('06f8aabf9c48b7ae375e2fb5f5207c2ed2c62e8a9ddc6f4cdd7201babc7e091e', 'hex'));

  it('G1Encode', () => {
    expect(Buffer.from(G1Encode(sample.getPublicKeyG1())).toString('hex')).toEqual('0306e50ce24f93cd9d36db6f8f73bea8fe2c916d46662800f7148ca6b137e23afce41d0c3fcc27dbfb2bd6d3c297e3eb95');
  });

  it('G1Decode', () => {
    const decoded = G1Decode(Buffer.from('0306e50ce24f93cd9d36db6f8f73bea8fe2c916d46662800f7148ca6b137e23afce41d0c3fcc27dbfb2bd6d3c297e3eb95', 'hex'));
    expect(decoded.toHex(true)).toEqual(sample.getPublicKeyG1().toHex(true));
  });

  it('G2Encode', () => {
    expect(Buffer.from(G2Encode(sample.getPublicKeyG2())).toString('hex')).toEqual('0310a1c1bea6fc02ed9448520f88575108f26fa4d40b88645c5c3479d4fc30b5c7f4121e61dbf95fd5477e8fa2d02449d5068bda9acae70ae6d7bc98694cf5edb13869a449b4a8d48dfef9199fbea4f5fd0d80381b967e497956672b3f4fa868ee');
  });

  it('G2Decode', () => {
    const decoded = G2Decode(Buffer.from('0310a1c1bea6fc02ed9448520f88575108f26fa4d40b88645c5c3479d4fc30b5c7f4121e61dbf95fd5477e8fa2d02449d5068bda9acae70ae6d7bc98694cf5edb13869a449b4a8d48dfef9199fbea4f5fd0d80381b967e497956672b3f4fa868ee', 'hex'));
    expect(decoded.toHex(true)).toEqual(sample.getPublicKeyG2().toHex(true));
  });
});
