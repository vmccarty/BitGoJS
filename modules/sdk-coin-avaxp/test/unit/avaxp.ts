import * as AvaxpLib from '../../src/lib';
import { TestBitGo, TestBitGoAPI } from '@bitgo/sdk-test';
import { AvaxP, TavaxP } from '../../src/';
import { randomBytes } from 'crypto';
import * as should from 'should';
import { BitGoAPI } from '@bitgo/sdk-api';
import { coins } from '@bitgo/statics';
import * as testData from '../resources/avaxp';
import { HalfSignedAccountTransaction, TransactionType } from '@bitgo/sdk-core';
import * as _ from 'lodash';

describe('Avaxp', function () {
  const coinName = 'avaxp';
  const tcoinName = 't' + coinName;
  let bitgo: TestBitGoAPI;
  let basecoin;

  before(function () {
    bitgo = TestBitGo.decorate(BitGoAPI, {
      env: 'mock',
    });
    bitgo.initializeTestVars();
    bitgo.safeRegister(coinName, AvaxP.createInstance);
    bitgo.safeRegister(tcoinName, TavaxP.createInstance);
    basecoin = bitgo.coin(tcoinName);
  });

  it('should instantiate the coin', function () {
    let localBasecoin = bitgo.coin(tcoinName);
    localBasecoin.should.be.an.instanceof(TavaxP);

    localBasecoin = bitgo.coin(coinName);
    localBasecoin.should.be.an.instanceof(AvaxP);
  });

  it('should return ' + tcoinName, function () {
    basecoin.getChain().should.equal(tcoinName);
  });

  it('should return full name', function () {
    basecoin.getFullName().should.equal('Testnet Avalanche P-Chain');
  });

  describe('Keypairs:', () => {
    it('should generate a keypair from random seed', function () {
      const keyPair = basecoin.generateKeyPair();
      keyPair.should.have.property('pub');
      keyPair.should.have.property('prv');
    });

    it('should generate a keypair from a seed', function () {
      const seedText = testData.SEED_ACCOUNT.seed;
      const seed = Buffer.from(seedText, 'hex');
      const keyPair = basecoin.generateKeyPair(seed);
      keyPair.pub.should.equal(testData.SEED_ACCOUNT.publicKey);
      keyPair.prv.should.equal(testData.SEED_ACCOUNT.privateKey);
    });

    it('should validate a public key', function () {
      const keyPair = basecoin.generateKeyPair();
      keyPair.should.have.property('pub');
      keyPair.should.have.property('prv');

      basecoin.isValidPub(keyPair.pub).should.equal(true);
    });

    it('should validate a private key', function () {
      const keyPair = basecoin.generateKeyPair();
      keyPair.should.have.property('pub');
      keyPair.should.have.property('prv');

      basecoin.isValidPrv(keyPair.prv).should.equal(true);
    });
  });

  describe('Sign Transaction', () => {
    const factory = new AvaxpLib.TransactionBuilderFactory(coins.get(tcoinName));

    it('should build transaction correctly', async () => {
      const txBuilder = new AvaxpLib.TransactionBuilderFactory(coins.get(tcoinName))
        .getValidatorBuilder()
        .threshold(testData.ADDVALIDATOR_SAMPLES.threshold)
        .locktime(testData.ADDVALIDATOR_SAMPLES.locktime)
        .fromPubKey(testData.ADDVALIDATOR_SAMPLES.pAddresses)
        .startTime(testData.ADDVALIDATOR_SAMPLES.startTime)
        .endTime(testData.ADDVALIDATOR_SAMPLES.endTime)
        .stakeAmount(testData.ADDVALIDATOR_SAMPLES.minValidatorStake)
        .delegationFeeRate(testData.ADDVALIDATOR_SAMPLES.delegationFee)
        .nodeID(testData.ADDVALIDATOR_SAMPLES.nodeID)
        .memo(testData.ADDVALIDATOR_SAMPLES.memo)
        .utxos(testData.ADDVALIDATOR_SAMPLES.outputs);
      const tx = await txBuilder.build();
      const txHex = tx.toBroadcastFormat();
      txHex.should.equal(testData.ADDVALIDATOR_SAMPLES.unsignedTxHex);
    });

    it('should be performed', async () => {
      const builder = factory.from(testData.ADDVALIDATOR_SAMPLES.unsignedTxHex);
      const tx = await builder.build();

      const params = {
        txPrebuild: {
          txHex: tx.toBroadcastFormat(),
        },
        prv: testData.ADDVALIDATOR_SAMPLES.privKey.prv1,
      };
      params.txPrebuild.txHex.should.equal(testData.ADDVALIDATOR_SAMPLES.unsignedTxHex);
      const halfSignedTransaction = await basecoin.signTransaction(params);
      halfSignedTransaction.should.have.property('halfSigned');
      (halfSignedTransaction as HalfSignedAccountTransaction)?.halfSigned?.txHex?.should.equal(
        testData.ADDVALIDATOR_SAMPLES.halfsigntxHex
      );
      params.txPrebuild.txHex = (halfSignedTransaction as HalfSignedAccountTransaction)?.halfSigned?.txHex;

      params.prv = testData.ADDVALIDATOR_SAMPLES.privKey.prv3;
      const signedTransaction = await basecoin.signTransaction(params);
      signedTransaction.should.not.have.property('halfSigned');
      signedTransaction.should.have.property('txHex');

      signedTransaction.txHex.should.equal(testData.ADDVALIDATOR_SAMPLES.fullsigntxHex);
    });

    it('should be rejected if invalid key', async () => {
      const invalidPrivateKey = 'AAAAA';
      const builder = factory.from(testData.ADDVALIDATOR_SAMPLES.unsignedTxHex);

      const tx = await builder.build();
      const params = {
        txPrebuild: {
          txHex: tx.toBroadcastFormat(),
        },
        prv: invalidPrivateKey,
      };

      await basecoin.signTransaction(params).should.be.rejected();
    });
  });

  describe('Sign Message', () => {
    it('should be performed', async () => {
      const keyPairToSign = new AvaxpLib.KeyPair();
      const prvKey = keyPairToSign.getPrivateKey();
      const keyPair = keyPairToSign.getKeys();
      const messageToSign = Buffer.from(randomBytes(32));
      const signature = await basecoin.signMessage(keyPair, messageToSign.toString('hex'));

      const verify = AvaxpLib.Utils.verifySignature(basecoin._staticsCoin.network, messageToSign, signature, prvKey!);
      verify.should.be.true();
    });

    it('should fail with missing private key', async () => {
      const keyPair = new AvaxpLib.KeyPair({
        pub: testData.SEED_ACCOUNT.publicKeyCb58,
      }).getKeys();
      const messageToSign = Buffer.from(randomBytes(32)).toString('hex');
      await basecoin.signMessage(keyPair, messageToSign).should.be.rejectedWith('Invalid key pair options');
    });
  });

  describe('Explain Transaction', () => {
    it('should explain a half signed AddValidator transaction', async () => {
      const txExplain = await basecoin.explainTransaction({
        halfSigned: { txHex: testData.ADDVALIDATOR_SAMPLES.halfsigntxHex },
      });
      txExplain.outputAmount.should.equal(testData.ADDVALIDATOR_SAMPLES.minValidatorStake);
      txExplain.type.should.equal(TransactionType.addValidator);
      txExplain.outputs[0].address.should.equal(testData.ADDVALIDATOR_SAMPLES.nodeID);
    });

    it('should explain a signed AddValidator transaction', async () => {
      const txExplain = await basecoin.explainTransaction({ txHex: testData.ADDVALIDATOR_SAMPLES.fullsigntxHex });
      txExplain.outputAmount.should.equal(testData.ADDVALIDATOR_SAMPLES.minValidatorStake);
      txExplain.type.should.equal(TransactionType.addValidator);
      txExplain.outputs[0].address.should.equal(testData.ADDVALIDATOR_SAMPLES.nodeID);
    });

    it('should fail when a tx is not passed as parameter', async () => {
      await basecoin.explainTransaction({}).should.be.rejectedWith('missing transaction hex');
    });
  });

  describe('Address Validation', function () {
    const keychains = [
      {
        id: '624f0dcc93cbcc0008d88df2369a565e',
        pub: 'xpub661MyMwAqRbcEeRkBciuaUfF4C1jgBcnj2RXdnt9gokx4CFRBUp4bsbk5hXHC1BrBDZLDNecVsUCMmoLpPhWdPZhPiTsHSoxNoGVW9KtiEQ',
        ethAddress: '0xcfbf38770af3a95da7998537a481434e2cb9b2fa',
        source: 'user',
        type: 'independent',
        encryptedPrv:
          '{"iv":"Z2XySTRNipFZ06/EXynwvA==","v":1,"iter":10000,"ks":256,"ts":64,"mode":"ccm","adata":"","cipher":"aes","salt":"KGRPbZ2jt1g=","ct":"szpCbDLFIlRZvCBV60SWBEMYXvny7YlBtu4ffjlctDQGjR4/+vfCkovgGHs+Xvf/eIlUM3Kicubg+Sdp61MImjMT/umZ3IJT1E2I9mM0QDqpzXlohTGnJ4vgfHgCz3QkB4uYm5mqaD4LtRbvZbGhGrc5jzrLzqQ="}',
      },
      {
        id: '624f0dcd93cbcc0008d88e0fc4261a38',
        pub: 'xpub661MyMwAqRbcGeqZVFgQfcD8zLoxaZL7y4cVAjhE8ybMTpvbppP6rc22a69BgcNVo74yL8fWPzNM5vAozBE7chzGYoPDJMyJ39F2HeAsGcn',
        ethAddress: '0xbf37f39208d77e3254b7efbcab1432b9c353e337',
        source: 'backup',
        type: 'independent',
        encryptedPrv:
          '{"iv":"T9gdJnSAEWFsLZ4cg9VA8g==","v":1,"iter":10000,"ks":256,"ts":64,"mode":"ccm","adata":"","cipher":"aes","salt":"FaLlns3mPiI=","ct":"QW5Zq9qJoDxDrK60zTAM6Lg+S4KP9FcEn9AHw5UIyakSBlD0XjVTluZ9PlTABjIlp9cQvMef/SH8Em1d4ash0PACoqBz2IxPwhW9h6uyQBdqk97iPrnM2rOQobsy9p0ILJM10fOgB+EEFYX5yQ5gyfEcK060j/Q="}',
      },
      {
        id: '624f0dce10610a0007fc5282353187ae',
        pub: 'xpub661MyMwAqRbcFVMAYJe51sgXaiFLeUb1v4u3B63CgBNMmMjtWBo32AS3bunsBUZMdi37pzovtEg5mVf6wBKayTYapGQRxymQjcmHaVmSPz8',
        ethAddress: '0x7527720b5638d2f5e2b272b20fc96d2223528d0e',
        source: 'bitgo',
        type: 'independent',
        isBitGo: true,
      },
    ];

    it('should fail to validate invalid address', function () {
      const invalidAddresses = ['', 'P-avax15x3z4rvk8e7vwa6g9lkyg89v5dwknp44858uex'];

      for (const address of invalidAddresses) {
        should.doesNotThrow(() => basecoin.isValidAddress(address));
        basecoin.isValidAddress(address).should.be.false();
      }
    });

    it('should validate address', function () {
      const validAddresses = [
        'P-fuji15x3z4rvk8e7vwa6g9lkyg89v5dwknp44858uex',
        'P-avax143q8lsy3y4ke9d6zeltre8u2ateed6uk9ka0nu',
      ];

      for (const address of validAddresses) {
        basecoin.isValidAddress(address).should.be.true();
      }
    });

    it('should fail to verify invalid address', function () {
      const invalidAddresses = [
        {
          address: 'P-fuji103cmntssp6qnucejahddy42wcy4qty0uj42822',
          keychains,
        },
        {
          address: 'P-avax143q8lsy3y4ke9d6zeltre8u2ateed6uk9ka0nu',
          keychains,
        },
      ];

      for (const address of invalidAddresses) {
        should.throws(() => basecoin.verifyAddress(address));
      }
    });

    it('should verify address', function () {
      const validAddresses = [
        {
          address: 'P-fuji15x3z4rvk8e7vwa6g9lkyg89v5dwknp44858uex',
          keychains,
        },
        {
          address: 'P-fuji1wq0d56pu54sgc5xpevm3ur6sf3l6kke70dz0l4',
          keychains,
        },
      ];

      for (const addressParams of validAddresses) {
        basecoin.verifyAddress(addressParams).should.be.true();
      }
    });
  });

  describe('verify transaction', function () {
    let newTxPrebuild;
    let newTxParams;

    const txPrebuild = {
      txHex:
        '00000000000c000000050000000000000000000000000000000000000000000000000000000000000000000000013d9bdac0ed1d761330cf680efdeb1a42159eb387d6d2950c96f7d28f61bbe2aa00000007000000003b58662700000000000000000000000200000003142b6a16450b8822fbc8a1532feb0e0a98edb6ecafbd5d1d92f5129affde6d2cd990759f7df4475bfbd692a4327cfc8361402072dddb1a1de227c71a00000001032b9f0f204c5ed1f2c479095a4a2d25965214de81efd2f75c9819cb41b6ec77000000003d9bdac0ed1d761330cf680efdeb1a42159eb387d6d2950c96f7d28f61bbe2aa0000000500000000770272670000000200000000000000010000003e003c4d616e75616c6c792061646420612064656c656761746f7220746f20746865207072696d617279207375626e65742077697468206d756c7469736967e25c9a09eb9c68d4807a39f97893facd9a6a7da10000000062bb03e60000000062e32556000000003b9aca00000000013d9bdac0ed1d761330cf680efdeb1a42159eb387d6d2950c96f7d28f61bbe2aa00000007000000003b9aca0000000000000000000000000200000003142b6a16450b8822fbc8a1532feb0e0a98edb6ecafbd5d1d92f5129affde6d2cd990759f7df4475bfbd692a4327cfc8361402072dddb1a1de227c71a0000000b00000000000000000000000200000003142b6a16450b8822fbc8a1532feb0e0a98edb6ecafbd5d1d92f5129affde6d2cd990759f7df4475bfbd692a4327cfc8361402072dddb1a1de227c71a00000000000000010000000900000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000142b6a16450b8822fbc8a1532feb0e0a98edb6ec0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
      txInfo: {},
    };

    const txParams = {
      recipients: [],
      type: 'addValidator',
      stakingOptions: {
        startTime: '1656423398',
        endTime: '1659053398',
        nodeID: 'NodeID-MdteS9U987PY7iwA5Pcz3sKVprJAbAvE7',
        amount: '1000000000', // 1 tavaxp
        delegationFeeRate: '10',
      },
      locktime: 0,
      memo: {
        value: 'Manually add a delegator to the primary subnet with multisig',
        type: 'text',
      },
    };

    before(function () {
      newTxPrebuild = () => {
        return _.cloneDeep(txPrebuild);
      };
      newTxParams = () => {
        return _.cloneDeep(txParams);
      };
    });

    it('should succeed to verify transactions', async function () {
      const txPrebuild = newTxPrebuild();
      const txParams = newTxParams();

      const validTransaction = await basecoin.verifyTransaction({ txParams, txPrebuild });
      validTransaction.should.equal(true);
    });

    it('should fail verify transactions when have different memo', async function () {
      const txParams = newTxParams();
      const txPrebuild = newTxPrebuild();
      txParams.memo = { value: 'errorMemo', type: 'text' };
      await basecoin
        .verifyTransaction({
          txParams,
          txPrebuild,
        })
        .should.be.rejectedWith('Tx memo does not match with expected txParams memo');
    });

    it('should fail verify transactions when have different locktime', async function () {
      const txParams = newTxParams();
      const txPrebuild = newTxPrebuild();
      txParams.locktime = 1;
      await basecoin
        .verifyTransaction({
          txParams,
          txPrebuild,
        })
        .should.be.rejectedWith('Tx locktime does not match with expected txParams locktime');
    });

    it('should fail verify transactions when have different type', async function () {
      const txParams = newTxParams();
      const txPrebuild = newTxPrebuild();
      txParams.type = 'addDelegator';
      await basecoin
        .verifyTransaction({
          txParams,
          txPrebuild,
        })
        .should.be.rejectedWith('Tx type does not match with expected txParams type');
    });

    it('should fail verify transactions when have different nodeId', async function () {
      const txParams = newTxParams();
      const txPrebuild = newTxPrebuild();
      txParams.stakingOptions.nodeID = 'NodeID-EZ38CcWHoSyoEfAkDN9zaieJ5Yq64YePY';
      await basecoin
        .verifyTransaction({
          txParams,
          txPrebuild,
        })
        .should.be.rejectedWith('Tx outputs does not match with expected txParams');
    });

    it('should fail verify transactions when have different amount', async function () {
      const txParams = newTxParams();
      const txPrebuild = newTxPrebuild();
      txParams.stakingOptions.amount = '2000000000';
      await basecoin
        .verifyTransaction({
          txParams,
          txPrebuild,
        })
        .should.be.rejectedWith('Tx outputs does not match with expected txParams');
    });
  });
});
