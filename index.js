import * as bech32 from 'bech32';
import bs58check from 'bs58check';
import bufferEquals from 'buffer-equals';
import createHash from 'create-hash';
import * as secp256k1 from 'secp256k1';
import * as varuint from 'varuint-bitcoin';

const SEGWIT_TYPES = {
  P2WPKH: 'p2wpkh',
  P2SH_P2WPKH: 'p2sh(p2wpkh)',
};

function sha256(buffer) {
  return createHash('sha256').update(buffer).digest();
}

function hash256(buffer) {
  return sha256(sha256(buffer));
}

function hash160(buffer) {
  return createHash('ripemd160').update(sha256(buffer)).digest();
}

function encodeSignature(signature, recovery, compressed, segwitType) {
  if (segwitType !== undefined) {
    recovery += 8;
    if (segwitType === SEGWIT_TYPES.P2WPKH) recovery += 4;
  } else {
    if (compressed) recovery += 4;
  }
  return Buffer.concat([Buffer.alloc(1, recovery + 27), signature]);
}

function decodeSignature(buffer) {
  if (buffer.length !== 65) throw new Error('Invalid signature length');

  const flagByte = buffer.readUInt8(0) - 27;
  if (flagByte > 15 || flagByte < 0) {
    throw new Error('Invalid signature parameter');
  }

  return {
    compressed: !!(flagByte & 12),
    segwitType: !(flagByte & 8)
      ? null
      : !(flagByte & 4)
      ? SEGWIT_TYPES.P2SH_P2WPKH
      : SEGWIT_TYPES.P2WPKH,
    recovery: flagByte & 3,
    signature: buffer.slice(1),
  };
}

function magicHash(message, messagePrefix = '\u0018Telestai Signed Message:\n') {
  if (!Buffer.isBuffer(messagePrefix)) {
    messagePrefix = Buffer.from(messagePrefix, 'utf8');
  }
  if (!Buffer.isBuffer(message)) {
    message = Buffer.from(message, 'utf8');
  }

  const messageVISize = varuint.encodingLength(message.length);
  const buffer = Buffer.allocUnsafe(
    messagePrefix.length + messageVISize + message.length
  );

  messagePrefix.copy(buffer, 0);
  varuint.encode(message.length, buffer, messagePrefix.length);
  message.copy(buffer, messagePrefix.length + messageVISize);

  return hash256(buffer);
}

function prepareSign(messagePrefixArg, sigOptions = {}) {
  let { segwitType, extraEntropy } = sigOptions;
  if (typeof segwitType === 'string' || segwitType instanceof String) {
    segwitType = segwitType.toLowerCase();
  }

  if (
    segwitType &&
    segwitType !== SEGWIT_TYPES.P2SH_P2WPKH &&
    segwitType !== SEGWIT_TYPES.P2WPKH
  ) {
    throw new Error(
      'Unrecognized segwitType: use "' +
        SEGWIT_TYPES.P2SH_P2WPKH +
        '" or "' +
        SEGWIT_TYPES.P2WPKH +
        '"'
    );
  }

  return {
    messagePrefixArg,
    segwitType,
    extraEntropy,
  };
}

function sign(message, privateKey, compressed = true, messagePrefix, sigOptions) {
  const { messagePrefixArg, segwitType, extraEntropy } = prepareSign(
    messagePrefix,
    sigOptions
  );
  const hash = magicHash(message, messagePrefixArg);

  const { signature, recovery } = secp256k1.ecdsaSign(hash, privateKey);

  return encodeSignature(signature, recovery, compressed, segwitType);
}

function signAsync(message, privateKey, compressed = true, messagePrefix, sigOptions) {
  return Promise.resolve()
    .then(() => {
      const { messagePrefixArg, segwitType, extraEntropy } = prepareSign(
        messagePrefix,
        sigOptions
      );
      const hash = magicHash(message, messagePrefixArg);

      return secp256k1.ecdsaSign(hash, privateKey);
    })
    .then(({ signature, recovery }) => {
      return encodeSignature(signature, recovery, compressed, sigOptions.segwitType);
    });
}

function segwitRedeemHash(publicKeyHash) {
  const redeemScript = Buffer.concat([Buffer.from('0014', 'hex'), publicKeyHash]);
  return hash160(redeemScript);
}

function decodeBech32(address) {
  const result = bech32.decode(address);
  const data = bech32.fromWords(result.words.slice(1));
  return Buffer.from(data);
}

function verify(message, address, signature, messagePrefix, checkSegwitAlways) {
  if (!Buffer.isBuffer(signature)) signature = Buffer.from(signature, 'base64');

  const parsedSignature = decodeSignature(signature);
  const hash = magicHash(message, messagePrefix);

  const publicKey = secp256k1.ecdsaRecover(
    parsedSignature.signature,
    parsedSignature.recovery,
    hash,
    parsedSignature.compressed
  );
  const publicKeyHash = hash160(publicKey);
  let actual, expected;

  if (parsedSignature.segwitType) {
    if (parsedSignature.segwitType === SEGWIT_TYPES.P2SH_P2WPKH) {
      actual = segwitRedeemHash(publicKeyHash);
      expected = bs58check.decode(address).slice(1);
    } else {
      actual = publicKeyHash;
      expected = decodeBech32(address);
    }
  } else {
    actual = publicKeyHash;
    expected = bs58check.decode(address).slice(1);
  }

  return bufferEquals(actual, expected);
}

// Export the necessary functions
export { magicHash, sign, signAsync, verify };

