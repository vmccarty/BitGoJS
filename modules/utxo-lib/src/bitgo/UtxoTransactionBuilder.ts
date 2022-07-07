import { TxOutput, Transaction, TransactionBuilder } from 'dogecoinjs-lib';
// eslint-disable-next-line
import * as bitcoinjs from 'dogecoinjs-lib';
import { Network } from '..';
import { UtxoTransaction } from './UtxoTransaction';

export interface TxbSignArg<TNumber extends number | bigint = number> {
  prevOutScriptType: string;
  vin: number;
  keyPair: bitcoinjs.ECPair.Signer;
  redeemScript?: Buffer;
  hashType?: number;
  witnessValue?: TNumber;
  witnessScript?: Buffer;
  controlBlock?: Buffer;
}

export class UtxoTransactionBuilder<
  TNumber extends number | bigint = number,
  T extends UtxoTransaction<TNumber> = UtxoTransaction<TNumber>
> extends TransactionBuilder<TNumber> {
  constructor(network: Network, txb?: TransactionBuilder<TNumber>, prevOutputs?: TxOutput<TNumber>[]) {
    super();
    this.network = network as bitcoinjs.Network;

    (this as any).__TX = this.createInitialTransaction(network, (txb as any)?.__TX);

    if (txb) {
      (this as any).__INPUTS = (txb as any).__INPUTS;
    }

    if (prevOutputs) {
      const txbInputs = (this as any).__INPUTS;
      if (prevOutputs.length !== txbInputs.length) {
        throw new Error(`prevOuts must match txbInput length`);
      }
      prevOutputs.forEach((o, i) => {
        txbInputs[i].value = o.value;
        txbInputs[i].prevOutScript = o.script;
      });
    }
  }

  createInitialTransaction(network: Network, tx?: Transaction<TNumber>): UtxoTransaction<TNumber> {
    return new UtxoTransaction<TNumber>(network, tx);
  }

  static fromTransaction<TNumber extends number | bigint = number>(
    tx: UtxoTransaction<TNumber>,
    network?: bitcoinjs.Network,
    prevOutputs?: TxOutput<TNumber>[]
  ): UtxoTransactionBuilder<TNumber> {
    return new UtxoTransactionBuilder<TNumber>(
      tx.network,
      TransactionBuilder.fromTransaction<TNumber>(tx),
      prevOutputs
    );
  }

  get tx(): T {
    return (this as any).__TX;
  }

  build(): T {
    return super.build() as T;
  }

  buildIncomplete(): T {
    return super.buildIncomplete() as T;
  }

  sign(
    signParams: number | TxbSignArg<TNumber>,
    keyPair?: bitcoinjs.ECPair.Signer,
    redeemScript?: Buffer,
    hashType?: number,
    witnessValue?: TNumber,
    witnessScript?: Buffer
  ): void {
    // Regular bitcoin p2sh-p2ms inputs do not include the input amount (value) in the signature and
    // thus do not require the parameter `value` to be set.
    // For bitcoincash and bitcoinsv p2sh-p2ms inputs, the value parameter *is* required however.
    // Since the `value` parameter is not passed to the legacy hashing method, we must store it
    // on the transaction input object.

    if (typeof signParams === 'number') {
      if (typeof witnessValue === 'number' || typeof witnessValue === 'bigint') {
        (this.tx.ins[signParams] as any).value = witnessValue;
      }

      return super.sign(signParams, keyPair, redeemScript, hashType, witnessValue, witnessScript);
    }

    if (signParams.witnessValue !== undefined) {
      (this.tx.ins[signParams.vin] as any).value = signParams.witnessValue;
    }
    // When calling the sign method via TxbSignArg, the `value` parameter is actually not permitted
    // to be set for p2sh-p2ms transactions.
    if (signParams.prevOutScriptType === 'p2sh-p2ms') {
      delete signParams.witnessValue;
    }
    return super.sign(signParams);
  }
}
