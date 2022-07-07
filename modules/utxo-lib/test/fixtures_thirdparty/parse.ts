import * as assert from 'assert';
import { getNetworkList, getNetworkName, isBitcoinGold, isMainnet, isZcash } from '../../src/networks';
import {
  sigHashTestFile,
  SigHashTestVector,
  testFixtureArray,
  txValidTestFile,
  TxValidVector,
  ZcashSigHashTestVector,
} from './fixtures';

import { parseTransactionRoundTrip } from '../transaction_util';
import { UtxoTransaction } from '../../src/bitgo/UtxoTransaction';
import { ZcashNetwork, ZcashTransaction } from '../../src/bitgo/zcash/ZcashTransaction';

describe('Third-Party Fixtures', function () {
  getNetworkList()
    .filter(isMainnet)
    .forEach((network) => {
      describe(`parse ${getNetworkName(network)}`, function () {
        function runCheckHashForSignature(v: SigHashTestVector | ZcashSigHashTestVector, i: number) {
          const [rawTransaction, script, inputIndex, hashType, ...rest] = v;
          const buffer = Buffer.from(rawTransaction, 'hex');
          let transaction, signatureHash;
          if (isZcash(network)) {
            [, /* branchId ,*/ signatureHash] = rest as [number, string];
            transaction = ZcashTransaction.fromBufferZcash(buffer, false, network as ZcashNetwork);
          } else {
            [signatureHash] = rest as [string];
            transaction = parseTransactionRoundTrip(buffer, network);
          }
          const usesForkId = (hashType & UtxoTransaction.SIGHASH_FORKID) > 0;
          if (isBitcoinGold(network) && usesForkId) {
            // Bitcoin Gold does not test transactions where FORKID is set 🤷
            // https://github.com/BTCGPU/BTCGPU/blob/163928af05/src/test/sighash_tests.cpp#L194-L195
            return;
          }

          const isSegwit = transaction.ins[inputIndex].witness?.length > 0;
          let hash;
          if (isSegwit) {
            hash = transaction.hashForWitnessV0(inputIndex, Buffer.from(script, 'hex'), 0, hashType);
          } else {
            (transaction.ins[inputIndex] as any).value = 0;
            hash = transaction.hashForSignature(inputIndex, Buffer.from(script, 'hex'), hashType);
          }
          const refSignatureHash = Buffer.from(signatureHash, 'hex').reverse();
          assert.strict(refSignatureHash.equals(hash));
        }

        testFixtureArray(network, sigHashTestFile, function (vectors: SigHashTestVector[]) {
          const zcashSubset = [48, 111, 114, 152, 157, 237, 241, 250, 280, 392, 461];
          vectors.forEach((v, i) => {
            if (isZcash(network) && !zcashSubset.includes(i)) {
              return;
            }
            runCheckHashForSignature(v, i);
          });
        });

        testFixtureArray(network, txValidTestFile, function (vectors: TxValidVector[]) {
          vectors.forEach((v: TxValidVector, i) => {
            const [, /* inputs , */ txHex] = v;
            parseTransactionRoundTrip(Buffer.from(txHex, 'hex'), network);
          });
        });
      });
    });
});
