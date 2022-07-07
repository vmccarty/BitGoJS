import * as bitcoinjs from 'bitcoinjs-lib';
import * as dogecoinjs from 'dogecoinjs-lib';
import { Network } from '../../networks';
import { UtxoTransactionBuilder } from '../UtxoTransactionBuilder';
import { DashTransaction } from './DashTransaction';
import { UtxoTransaction } from '../UtxoTransaction';

export class DashTransactionBuilder extends UtxoTransactionBuilder<number, DashTransaction> {
  constructor(network: Network, txb?: UtxoTransactionBuilder) {
    super(network, txb);
  }

  createInitialTransaction(network: Network, tx?: dogecoinjs.Transaction): DashTransaction {
    return new DashTransaction(network, tx as UtxoTransaction);
  }

  setType(type: number): void {
    this.tx.type = type;
  }

  setExtraPayload(extraPayload?: Buffer): void {
    this.tx.extraPayload = extraPayload;
  }

  static fromTransactionDash(
    tx: DashTransaction,
    network?: bitcoinjs.Network,
    prevOutput?: bitcoinjs.TxOutput[]
  ): DashTransactionBuilder {
    const txb = new DashTransactionBuilder(tx.network, UtxoTransactionBuilder.fromTransaction(tx, network, prevOutput));
    txb.setType(tx.type);
    txb.setExtraPayload(tx.extraPayload);
    return txb;
  }
}
