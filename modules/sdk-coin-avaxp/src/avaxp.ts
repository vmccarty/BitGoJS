import { AvalancheNetwork, BaseCoin as StaticsBaseCoin, CoinFamily, coins } from '@bitgo/statics';
import {
  BaseCoin,
  BitGoBase,
  KeyPair,
  VerifyAddressOptions,
  SignedTransaction,
  ParseTransactionOptions,
  MethodNotImplementedError,
  BaseTransaction,
  InvalidTransactionError,
  FeeEstimateOptions,
  SigningError,
  TransactionType,
  InvalidAddressError,
  UnexpectedAddressError,
} from '@bitgo/sdk-core';
import * as AvaxpLib from './lib';
import {
  AvaxpSignTransactionOptions,
  TransactionFee,
  ExplainTransactionOptions,
  AvaxpVerifyTransactionOptions,
} from './iface';
import * as _ from 'lodash';

export class AvaxP extends BaseCoin {
  protected readonly _staticsCoin: Readonly<StaticsBaseCoin>;

  constructor(bitgo: BitGoBase, staticsCoin?: Readonly<StaticsBaseCoin>) {
    super(bitgo);

    if (!staticsCoin) {
      throw new Error('missing required constructor parameter staticsCoin');
    }

    this._staticsCoin = staticsCoin;
  }

  static createInstance(bitgo: BitGoBase, staticsCoin?: Readonly<StaticsBaseCoin>): BaseCoin {
    return new AvaxP(bitgo, staticsCoin);
  }

  getChain(): string {
    return this._staticsCoin.name;
  }
  getFamily(): CoinFamily {
    return this._staticsCoin.family;
  }
  getFullName(): string {
    return this._staticsCoin.fullName;
  }
  getBaseFactor(): string | number {
    return Math.pow(10, this._staticsCoin.decimalPlaces);
  }

  supportsStaking(): boolean {
    return true;
  }

  async verifyTransaction(params: AvaxpVerifyTransactionOptions): Promise<boolean> {
    const txHex = params.txPrebuild && params.txPrebuild.txHex;
    if (!txHex) {
      throw new Error('missing required tx prebuild property txHex');
    }
    let tx;
    try {
      const txBuilder = this.getBuilder().from(txHex);
      tx = await txBuilder.build();
    } catch (error) {
      console.log({ error });
      throw new Error('Invalid transaction');
    }
    const explainedTx = tx.explainTransaction();
    const txJson = tx.toJson();

    const { type, stakingOptions, locktime, memo } = params.txParams;
    if (!type || txJson.type !== TransactionType[type]) {
      throw new Error('Tx type does not match with expected txParams type');
    }
    if (memo && txJson.memo !== memo.value) {
      throw new Error('Tx memo does not match with expected txParams memo');
    }
    if (locktime && txJson.locktime !== locktime) {
      throw new Error('Tx locktime does not match with expected txParams locktime');
    }
    if (!params.txParams.recipients || params.txParams.recipients.length === 0) {
      const filteredRecipients = [{ address: stakingOptions.nodeID, amount: stakingOptions.amount }];
      const filteredOutputs = explainedTx.outputs.map((output) => _.pick(output, ['address', 'amount']));

      if (!_.isEqual(filteredOutputs, filteredRecipients)) {
        throw new Error('Tx outputs does not match with expected txParams');
      }
      if (stakingOptions.amount !== explainedTx.outputAmount) {
        throw new Error('Tx total amount does not match with expected total amount field');
      }
    }
    return true;
  }

  /**
   * Check if address is valid, then make sure it matches the root address.
   *
   * @param {VerifyAddressOptions} params address and rootAddress to verify
   */
  isWalletAddress(params: VerifyAddressOptions): boolean {
    const { address, keychains } = params;
    if (!this.isValidAddress(address)) {
      throw new InvalidAddressError(`invalid address: ${address}`);
    }
    if (!keychains || keychains.length !== 3) {
      throw new Error('Invalid keychains');
    }
    const walletAddress = keychains.map((keychain) =>
      new AvaxpLib.KeyPair({ pub: keychain.pub }).getAddress(this._staticsCoin.network.type)
    );
    console.log({ walletAddress });

    if (!walletAddress.some((add) => add.endsWith(address))) {
      throw new UnexpectedAddressError(`address validation failure: ${address} is not of this wallet`);
    }
    return true;
  }

  /**
   * Generate Avaxp key pair
   *
   * @param {Buffer} seed - Seed from which the new keypair should be generated, otherwise a random seed is used
   * @returns {Object} object with generated pub and prv
   */
  generateKeyPair(seed?: Buffer): KeyPair {
    const keyPair = seed ? new AvaxpLib.KeyPair({ seed }) : new AvaxpLib.KeyPair();
    const keys = keyPair.getKeys();

    if (!keys.prv) {
      throw new Error('Missing prv in key generation.');
    }

    return {
      pub: keys.pub,
      prv: keys.prv,
    };
  }

  /**
   * Return boolean indicating whether input is valid public key for the coin
   *
   * @param {string} pub the prv to be checked
   * @returns is it valid?
   */
  isValidPub(pub: string): boolean {
    try {
      new AvaxpLib.KeyPair({ pub });
      return true;
    } catch (e) {
      return false;
    }
  }

  /**
   * Return boolean indicating whether input is valid private key for the coin
   *
   * @param {string} prv the prv to be checked
   * @returns is it valid?
   */
  isValidPrv(prv: string): boolean {
    try {
      new AvaxpLib.KeyPair({ prv });
      return true;
    } catch (e) {
      return false;
    }
  }

  isValidAddress(address: string): boolean {
    return AvaxpLib.Utils.isValidAddress(address);
  }

  /**
   * Signs Avaxp transaction
   */
  async signTransaction(params: AvaxpSignTransactionOptions): Promise<SignedTransaction> {
    const txBuilder = this.getBuilder().from(params.txPrebuild.txHex);
    const key = params.prv;
    txBuilder.sign({ key });

    const transaction: BaseTransaction = await txBuilder.build();
    if (!transaction) {
      throw new InvalidTransactionError('Error while trying to build transaction');
    }
    const response = {
      txHex: transaction.toBroadcastFormat(),
    };

    return transaction.signature.length >= 2 ? response : { halfSigned: response };
  }

  async feeEstimate(params: FeeEstimateOptions): Promise<TransactionFee> {
    return { fee: (this._staticsCoin.network as AvalancheNetwork).txFee.toString() };
  }

  parseTransaction(params: ParseTransactionOptions): Promise<ParseTransactionOptions> {
    throw new MethodNotImplementedError('parseTransaction method not implemented');
  }

  /**
   * Explain a Avaxp transaction from txHex
   * @param params
   * @param callback
   */
  async explainTransaction(params: ExplainTransactionOptions): Promise<AvaxpLib.TransactionExplanation> {
    const txHex = params.txHex ?? params?.halfSigned?.txHex;
    if (!txHex) {
      throw new Error('missing transaction hex');
    }
    try {
      const txBuilder = this.getBuilder().from(txHex);
      const tx = await txBuilder.build();
      return tx.explainTransaction();
    } catch (e) {
      throw new Error(`Invalid transaction: ${e.message}`);
    }
  }

  async signMessage(key: KeyPair, message: string | Buffer): Promise<Buffer> {
    const prv = new AvaxpLib.KeyPair(key).getPrivateKey();
    if (!prv) {
      throw new SigningError('Invalid key pair options');
    }
    if (typeof message === 'string') {
      message = Buffer.from(message, 'hex');
    }
    return AvaxpLib.Utils.createSignature(this._staticsCoin.network as AvalancheNetwork, message, prv);
  }

  private getBuilder(): AvaxpLib.TransactionBuilderFactory {
    return new AvaxpLib.TransactionBuilderFactory(coins.get(this.getChain()));
  }
}
