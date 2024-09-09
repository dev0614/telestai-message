import { expect } from 'chai';
import { sign, verify } from '../index.js'; // Import only the required functions

describe('Telestai Message Signing and Verification', () => {
  const privateKey = Buffer.from('KxUQGuxHdwR2QxWquTZaCkAZbQEYqXRC2sSombTeRXZrSyU5eSrk', 'hex');
  const message = 'Hello, Telestai!';
  const address = 'TarfC8z5xJifj3VN4Mrr3kFrH2bCmNEjNG';

  let signature;

  it('should sign a message', () => {
    signature = sign(message, privateKey, true);
    expect(signature).to.be.an.instanceof(Buffer);
    expect(signature.length).to.be.greaterThan(0);
  });

  it('should verify a signed message', () => {
    const isValid = verify(message, address, signature);
    expect(isValid).to.be.true;
  });
});
