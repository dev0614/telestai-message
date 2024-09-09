export interface SignatureOptions {
  segwitType?: 'p2wpkh' | 'p2sh(p2wpkh)';
  extraEntropy?: Buffer;
}

export interface Signer {
  sign(hash: Buffer, extraEntropy?: Buffer): { signature: Buffer; recovery: number };
}

export interface SignerAsync {
  sign(hash: Buffer, extraEntropy?: Buffer): Promise<{ signature: Buffer; recovery: number }>;
}

export function magicHash(message: string | Buffer, messagePrefix?: string): Buffer;

export function sign(
  message: string | Buffer,
  privateKey: Buffer | Signer,
  compressed?: boolean,
  sigOptions?: SignatureOptions
): Buffer;

export function signAsync(
  message: string | Buffer,
  privateKey: Buffer | SignerAsync | Signer,
  compressed?: boolean,
  sigOptions?: SignatureOptions
): Promise<Buffer>;

export function verify(
  message: string | Buffer,
  address: string,
  signature: string | Buffer,
  messagePrefix?: string,
  checkSegwitAlways?: boolean
): boolean;
