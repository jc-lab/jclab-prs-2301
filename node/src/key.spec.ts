import {
  PrivateKey
} from './index';

describe('PrivateKey', function () {
  const sample = PrivateKey.fromBytes(Buffer.from('06f8aabf9c48b7ae375e2fb5f5207c2ed2c62e8a9ddc6f4cdd7201babc7e091e', 'hex'));
  const generated = PrivateKey.generate();

  it('getScalar', () => {
    expect(sample.getScalar()).toEqual(3153233626252037211154788955342207393011830119130551050952634150047279089950n);
  });

  it('getEncodedPublicKeyG1', () => {
    expect(Buffer.from(sample.getEncodedPublicKeyG1()).toString('hex')).toEqual('0306e50ce24f93cd9d36db6f8f73bea8fe2c916d46662800f7148ca6b137e23afce41d0c3fcc27dbfb2bd6d3c297e3eb95');
  });

  it('getEncodedPublicKeyG2', () => {
    expect(Buffer.from(sample.getEncodedPublicKeyG2()).toString('hex')).toEqual('0310a1c1bea6fc02ed9448520f88575108f26fa4d40b88645c5c3479d4fc30b5c7f4121e61dbf95fd5477e8fa2d02449d5068bda9acae70ae6d7bc98694cf5edb13869a449b4a8d48dfef9199fbea4f5fd0d80381b967e497956672b3f4fa868ee');
  });

  it('getBytes-fromBytes', () => {
    const bytes = generated.getBytes();
    const privateKey = PrivateKey.fromBytes(bytes);
    expect(privateKey.getScalar()).toEqual(generated.getScalar());
  });

  it('getScalar-fromScalar', () => {
    const bytes = generated.getScalar();
    const privateKey = PrivateKey.fromScalar(bytes);
    expect(privateKey.getScalar()).toEqual(generated.getScalar());
  });
});
