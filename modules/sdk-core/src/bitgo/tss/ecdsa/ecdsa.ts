import { ECDSA, Ecdsa } from './../../../account-lib/mpc/tss';
import { DecryptableNShare, CombinedKey, SigningMaterial, EncryptedNShare } from './types';
import { encryptAndSignText, readSignedMessage } from './../../utils';
import { ShareKeyPosition } from '../types';
import { BitGoBase } from '../../bitgoBase';
import { KShare, MUShare, SShare } from 'modules/sdk-core/src/account-lib/mpc/tss/ecdsa/types';

type NShare = ECDSA.NShare;
type KeyShare = ECDSA.KeyShare;
type XShare = ECDSA.XShare;
type YShare = ECDSA.YShare;
type SignShare = ECDSA.SignShareRT;
type WShare = ECDSA.WShare;
type AShare = ECDSA.AShare;
type GShare = ECDSA.GShare;
type OShare = ECDSA.OShare;
type DShare = ECDSA.DShare;
type createUserGammaShareRT = ECDSA.SignConvertRT; // Recheck
type createUserOmicronShareRT = ECDSA.SignCombineRT;
type SignatureShare = ECDSA.SignRT;

export enum SendShareType {
  KShare = 'KShare',
  MUShare = 'MUShare',
  SShare = 'SShare',
}

const MPC = new Ecdsa();

/**
 * Combines NShares to combine the final TSS key
 * This can only be used to create the User or Backup key since it requires the common keychain from BitGo first
 *
 * @param keyShare - TSS key share
 * @param encryptedNShares - encrypted NShares with information on how to decrypt
 * @param commonKeychain - expected common keychain of the combined key
 * @returns {CombinedKey} combined TSS key
 */
export async function createCombinedKey(
  keyShare: KeyShare,
  encryptedNShares: DecryptableNShare[],
  commonKeychain: string
): Promise<CombinedKey> {
  const nShares: NShare[] = [];

  let bitgoNShare: NShare | undefined;
  let userNShare: NShare | undefined;
  let backupNShare: NShare | undefined;

  for (const encryptedNShare of encryptedNShares) {
    const privateShare = await readSignedMessage(
      encryptedNShare.nShare.encryptedPrivateShare,
      encryptedNShare.senderPublicArmor,
      encryptedNShare.recipientPrivateArmor
    );

    const nShare: NShare = {
      i: encryptedNShare.nShare.i,
      j: encryptedNShare.nShare.j,
      y: encryptedNShare.nShare.publicShare.slice(0, 65),
      u: privateShare,
      n: encryptedNShare.nShare.publicShare.slice(129),
      chaincode: encryptedNShare.nShare.publicShare.slice(65, 129),
    };

    switch (encryptedNShare.nShare.j) {
      case 1:
        userNShare = nShare;
        break;
      case 2:
        backupNShare = nShare;
        break;
      case 3:
        bitgoNShare = nShare;
        break;
      default:
        throw new Error('Invalid NShare index');
    }

    nShares.push(nShare);
  }

  if (!bitgoNShare) {
    throw new Error('Missing BitGo N Share');
  }

  const combinedKey = MPC.keyCombine(keyShare.pShare, nShares);
  if (combinedKey.xShare.y + combinedKey.xShare.chaincode !== commonKeychain) {
    throw new Error('Common keychains do not match');
  }

  const signingMaterial: SigningMaterial = {
    pShare: keyShare.pShare,
    bitgoNShare,
    backupNShare,
    userNShare,
  };

  return {
    signingMaterial,
    commonKeychain,
  };
}

/**
 * Creates the SignShare with User XShare and YShare Corresponding to BitGo
 *
 * @param {XShare} xShare User secret xShare
 * @param {YShare} yShare YShare from Bitgo
 * @returns {Promise<SignShare>}
 */
export async function createUserSignShare(xShare: XShare, yShare: YShare): Promise<SignShare> {
  if (xShare.i !== ShareKeyPosition.USER) {
    throw new Error(`Invalid XShare, XShare doesn't belong to the User`);
  }

  if (yShare.i !== ShareKeyPosition.USER && yShare.j !== ShareKeyPosition.BITGO) {
    throw new Error('Invalid YShare provided for sign');
  }
  return MPC.signShare(xShare, yShare);
}

// Implement Send User to Bitgo KShare

/**
 * Sends the User KShare to Bitgo
 * @param {BitGoBase} bitgo - the bitgo instance
 * @param {String} walletId - the wallet id
 * @param {String} txRequestId - the txRequest Id
 * @param {KShare} userKShare - the user KShare
 * @returns {Promise<void>}
 */
export async function offerUserToBitgoKShare(
  bitgo: BitGoBase,
  walletId: string,
  txRequestId: string,
  userKShare: KShare
): Promise<void> {
  if (userKShare.i !== ShareKeyPosition.BITGO || userKShare.j !== ShareKeyPosition.USER) {
    throw new Error('Invalid KShare, is not from User to Bitgo');
  }
  await sendShareToBitgo(bitgo, walletId, txRequestId, SendShareType.KShare, userKShare);
}

// Implement Get Bitgo to user AShare

/**
 * Gets the Bitgo to User AShare from Bitgo
 *
 * @param {BitGoBase} bitgo - the bitgo instance
 * @param {String} walletId - the wallet id
 * @param {String} txRequestId - the txRequest Id
 * @returns {Promise<AShare>}
 */
export async function getBitgoToUserAShare(bitgo: BitGoBase, walletId: string, txRequestId: string): Promise<AShare> {
  const txRequest = await getTxRequest(bitgo, walletId, txRequestId);
  const aShare = txRequest.aShare;
  if (!aShare) {
    throw new Error(`No signatures shares found for id: ${txRequestId}`);
  }

  return aShare;
}

// Implement createUserGamma Share

/**
 * Creates the Gamma Share with User WShare and AShare From BitGo
 *
 * @param {WShare} wShare User WShare
 * @param {AShare} aShare AShare from Bitgo
 * @returns {Promise<createUserGammaShareRT>}
 */
export async function createUserGammaShare(wShare: WShare, aShare: AShare): Promise<createUserGammaShareRT> {
  if (wShare.i !== ShareKeyPosition.USER) {
    throw new Error(`Invalid WShare, doesn't belong to the User`);
  }
  if (aShare.i !== ShareKeyPosition.USER || aShare.j !== ShareKeyPosition.BITGO) {
    throw new Error('Invalid AShare, is not from Bitgo to User');
  }

  return MPC.signConvert({ wShare, aShare });
}

// Implement Send User to Bitgo MuShare

/**
 * Sends the User MUShare to Bitgo
 * @param {BitGoBase} bitgo - the bitgo instance
 * @param {String} walletId - the wallet id
 * @param {String} txRequestId - the txRequest Id
 * @param {MUShare} userMUShare - the user MUShare
 * @returns {Promise<void>}
 */
export async function offerUserToBitgoMUShare(
  bitgo: BitGoBase,
  walletId: string,
  txRequestId: string,
  userMUShare: MUShare
): Promise<void> {
  if (userMUShare.i !== ShareKeyPosition.BITGO || userMUShare.j !== ShareKeyPosition.USER) {
    throw new Error('Invalid MUShare, is not from User to Bitgo');
  }
  await sendShareToBitgo(bitgo, walletId, txRequestId, SendShareType.MUShare, userMUShare);
}

// Implement Create User Omicron Shares

/**
 * Creates the Omicron Share with User GShare and MUShare From BitGo
 *
 * @param {GShare} gShare User GShare
 * @returns {Promise<createUserGammaShareRT>}
 */
export async function createUserOmicronShare(gShare: GShare): Promise<createUserOmicronShareRT> {
  if (gShare.i !== ShareKeyPosition.USER) {
    throw new Error(`Invalid WShare, doesn't belong to the User`);
  }
  return MPC.signCombine({
    gShares: gShare, // Recheck
    signIndex: {
      i: ShareKeyPosition.BITGO,
      j: ShareKeyPosition.USER,
    },
  });
}

// Implement Get Bitgo Delta Shares

/**
 * Gets the Bitgo to User DShare from Bitgo
 *
 * @param {BitGoBase} bitgo - the bitgo instance
 * @param {String} walletId - the wallet id
 * @param {String} txRequestId - the txRequest Id
 * @returns {Promise<DShare>}
 */
export async function getBitgoToUserDShare(bitgo: BitGoBase, walletId: string, txRequestId: string): Promise<DShare> {
  const txRequest = await getTxRequest(bitgo, walletId, txRequestId);
  const dShare = txRequest.dShare;
  if (!dShare) {
    throw new Error(`No signatures shares found for id: ${txRequestId}`);
  }

  return dShare;
}

// Implement CreateUserSignature Shares

/**
 * Creates the Signature Share with User OShare and DShare From BitGo
 *
 * @param {OShare} oShare User OShare
 * @param {DShare} dShare DShare from bitgo
 * @param {Buffer} message message to perform sign
 * @returns {Promise<createUserSignShareRT>}
 */
export async function createUserSignatureShare(
  oShare: OShare,
  dShare: DShare,
  message: Buffer
): Promise<SignatureShare> {
  if (oShare.i !== ShareKeyPosition.USER) {
    throw new Error(`Invalid OShare, doesn't belong to the User`);
  }

  if (dShare.i !== ShareKeyPosition.BITGO && dShare.j !== ShareKeyPosition.USER) {
    throw new Error(`Invalid DShare, doesn't seem to be from BitGo`);
  }
  return MPC.sign(message, oShare, dShare);
}

// Implement Send User to Bitgo SignShare

/**
 * Sends the User SShare to Bitgo
 * @param {BitGoBase} bitgo - the bitgo instance
 * @param {String} walletId - the wallet id
 * @param {String} txRequestId - the txRequest Id
 * @param {SShare} userSShare - the user SShare
 * @returns {Promise<void>}
 */
export async function offerUserToBitgoSShare(
  bitgo: BitGoBase,
  walletId: string,
  txRequestId: string,
  userSShare: SShare
): Promise<void> {
  if (userSShare.i !== ShareKeyPosition.BITGO) {
    throw new Error('Invalid SShare, is not from User to Bitgo');
  }
  await sendShareToBitgo(bitgo, walletId, txRequestId, SendShareType.SShare, userSShare);
}

/**
 * Gets the latest Tx Request by id
 *
 * @param {BitGoBase} bitgo - the bitgo instance
 * @param {String} walletId - the wallet id
 * @param {String} txRequestId - the txRequest Id
 * @returns {Promise<TxRequest>}
 */
export async function getTxRequest(bitgo: BitGoBase, walletId: string, txRequestId: string): Promise<any> {
  const txRequestRes = await bitgo
    .get(bitgo.url('/wallet/' + walletId + '/txrequests', 2))
    .query({ txRequestIds: txRequestId, latest: 'true' })
    .result();

  if (txRequestRes.txRequests.length <= 0) {
    throw new Error(`Unable to find TxRequest with id ${txRequestId}`);
  }

  return txRequestRes.txRequests[0];
}

/**
 * Sends Share To Bitgo
 *
 * @param {BitGoBase} bitgo - the bitgo instance
 * @param {String} walletId - the wallet id  *
 * @param {String} txRequestId - the txRequest Id
 * @param {SignatureShareRecord} signatureShare - a Signature Share
 * @returns {Promise<SignatureShareRecord>} - a Signature Share
 */
export async function sendShareToBitgo(
  bitgo: BitGoBase,
  walletId: string,
  txRequestId: string,
  shareType: SendShareType,
  share: SignatureShare | MUShare | KShare
): Promise<any> {
  // TODO: Define return type here
  let payload = {};

  switch (shareType) {
    case SendShareType.KShare:
      payload = { KShare: share };
      break;
    case SendShareType.MUShare:
      payload = { MUShare: share };
      break;
    case SendShareType.SShare:
      payload = { SShare: share };
      break;
    default:
      throw 'Invalid Share given to send';
  }
  return bitgo
    .post(bitgo.url('/wallet/' + walletId + '/txrequests/' + txRequestId + '/signatureshares', 2)) // could change to more meaningful name
    .send({
      ...payload,
    })
    .result();
}
/**
 * Prepares a NShare to be exchanged with other key holders.
 * Output is in a format that is usable within BitGo's ecosystem.
 *
 * @param keyShare - TSS key share of the party preparing exchange materials
 * @param recipientIndex - index of the recipient (1, 2, or 3)
 * @param recipientGpgPublicArmor - recipient's public gpg key in armor format
 * @param senderGpgPrivateArmor - sender's private gpg key in armor format
 * @returns { EncryptedNShare } encrypted Y Share
 */
export async function encryptNShare(
  keyShare: KeyShare,
  recipientIndex: number,
  recipientGpgPublicArmor: string,
  senderGpgPrivateArmor: string
): Promise<EncryptedNShare> {
  const nShare = keyShare.nShares[recipientIndex];
  if (!nShare) {
    throw new Error('Invalid recipient');
  }

  const publicShare = keyShare.pShare.y + nShare.chaincode + nShare.n;
  const privateShare = nShare.u;

  const encryptedPrivateShare = await encryptAndSignText(privateShare, recipientGpgPublicArmor, senderGpgPrivateArmor);

  return {
    i: nShare.i,
    j: nShare.j,
    publicShare,
    encryptedPrivateShare,
  };
}
