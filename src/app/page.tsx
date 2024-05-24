"use client"

import { Address, BI, commons, config, Hash, hd, helpers, HexString, RPC, Script, Transaction } from '@ckb-lumos/lumos';
import { AuthResponse, connect as JoyIdConnect, initConfig, signRawTransaction } from '@joyid/ckb';
import {
  connect,
  watchAccount,
  disconnect,
  signMessage,
  createConfig,
  configureChains,
  mainnet,
} from '@wagmi/core';
import { InjectedConnector } from '@wagmi/core/connectors';
import { publicProvider } from '@wagmi/core/providers/public';
import { useState } from 'react';
import { motion } from "framer-motion";
import { cn } from "@/utils/cn";
import Image from 'next/image';
import { ethers } from 'ethers';
import { bytes, number } from '@ckb-lumos/codec';
import { bytifyRawString, createCluster, createSpore, defaultEmptyWitnessArgs, getSporeConfig, isScriptIdEquals, isScriptValueEquals, predefinedSporeConfigs, SporeConfig, updateWitnessArgs } from '@spore-sdk/core';
import { anyoneCanPay, common, omnilock, secp256k1Blake160 } from '@ckb-lumos/lumos/common-scripts';
import { getAnyoneCanPayMinimumCapacity, isAnyoneCanPay, isSameScript } from '@/utils/script';
import { blockchain } from '@ckb-lumos/base';
import { registerCustomLockScriptInfos } from '@ckb-lumos/lumos/common-scripts/common';
import { createJoyIDScriptInfo } from '@/utils/joyid';
import { ccc } from '@ckb-ccc/connector-react'

type Card = {
  id: number;
  content: JSX.Element | React.ReactNode | string;
  className: string;
  thumbnail: string;
};

export default function Home() {

  const [metamaskETHAddress, setMetamaskETHAddress] = useState<string>();
  const [metamaskCKBAddress, setMetamaskCKBAddress] = useState<string>();
  const [secp256k1Address, setSecp256k1Address] = useState<string>();
  const { wallet, open, disconnect } = ccc.useCcc();
  const [joyIdWallet, setJoyIDWallet] = useState<string>();
  const [joyIdPubKey, setJoyIdPubKey] = useState<string>();
  const [cccAddress, setCccAddress] = useState<string>();

  type Account = {
    lockScript: Script;
    address: Address;
    pubKey: string;
  };

  interface Secp256k1Wallet {
    lock: Script;
    address: Address;
    createAcpLock(props?: { minCkb?: number }): Script;
    signMessage(message: HexString): Hash;
    signTransaction(txSkeleton: helpers.TransactionSkeletonType): helpers.TransactionSkeletonType;
    signAndSendTransaction(txSkeleton: helpers.TransactionSkeletonType): Promise<Hash>;
  }

  /**
   * THIS IS FUCKING IMPORTANT ⚠️ 
   * THIS IS FUCKING IMPORTANT ⚠️
   * THIS IS FUCKING IMPORTANT ⚠️
   */
   config.initializeConfig(config.TESTNET);
   registerCustomLockScriptInfos([createJoyIDScriptInfo()])


  function formatString(str: string, maxLen: number = 15): string {
    console.log(str);
    if (str.length > maxLen) {
      return `${str.slice(0, 8)}......${str.slice(-4)}`;
    }
    return str;
  }

  function removeHexPrefix(str: string): string {
    return str.startsWith('0x') ? str.slice(2) : str;
  }

/**
 * Create a Secp256k1Blake160 Sign-all Wallet by a private key and a SporeConfig,
 * providing lock/address, and functions sign message/transaction and send the transaction on-chain.
 *
 * Note: The generated wallet also supports ACP (Anyone-can-pay) lock,
 * since the ACP lock is designed/implemented based on the Secp256k1Blake160 Sign-all lock.
 */
function createSecp256k1Wallet(privateKey: HexString, config: SporeConfig): Secp256k1Wallet {
  const Secp256k1Blake160 = config.lumos.SCRIPTS.SECP256K1_BLAKE160!;
  const AnyoneCanPay = config.lumos.SCRIPTS.ANYONE_CAN_PAY!;

  // Generate a lock script from the private key
  const blake160 = hd.key.privateKeyToBlake160(privateKey);
  const lock: Script = {
    codeHash: Secp256k1Blake160.CODE_HASH,
    hashType: Secp256k1Blake160.HASH_TYPE,
    args: blake160,
  };

  // Generate address from the lock script
  const address = helpers.encodeToAddress(lock, {
    config: config.lumos,
  });

  // Create an Anyone-can-pay lock script
  // minCkb: The minimal required digit of payment CKBytes.
  // Refer to: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0026-anyone-can-pay/0026-anyone-can-pay.md
  function createAcpLock(props?: { minCkb?: number }): Script {
    const minCkb = props?.minCkb;
    const minimalCkb = minCkb !== void 0 ? bytes.hexify(number.Uint8.pack(minCkb as number)) : '';
    return {
      codeHash: AnyoneCanPay.CODE_HASH,
      hashType: AnyoneCanPay.HASH_TYPE,
      args: `${blake160}${removeHexPrefix(minimalCkb)}`,
    };
  }

  // Sign for a message
  function signMessage(message: HexString): Hash {
    return hd.key.signRecoverable(message, privateKey);
  }

  // Sign prepared signing entries,
  // and then fill signatures into Transaction.witnesses
  function signTransaction(txSkeleton: helpers.TransactionSkeletonType): helpers.TransactionSkeletonType {
    const signingEntries = txSkeleton.get('signingEntries');
    const signatures = new Map<HexString, Hash>();
    const inputs = txSkeleton.get('inputs');

    let witnesses = txSkeleton.get('witnesses');
    for (let i = 0; i < signingEntries.size; i++) {
      const entry = signingEntries.get(i)!;
      if (entry.type === 'witness_args_lock') {
        const input = inputs.get(entry.index);
        if (!input) {
          continue;
        }
        if (
          !isScriptValueEquals(input.cellOutput.lock, lock) &&
          !isAcpLockMatches(input.cellOutput.lock, blake160, config)
        ) {
          continue;
        }
        if (!signatures.has(entry.message)) {
          const newSignature = signMessage(entry.message);
          signatures.set(entry.message, newSignature);
        }

        const signature = signatures.get(entry.message)!;
        const witness = witnesses.get(entry.index, defaultEmptyWitnessArgs);
        witnesses = witnesses.set(entry.index, updateWitnessArgs(witness, 'lock', signature));
      }
    }

    return txSkeleton.set('witnesses', witnesses);
  }

  // Sign the transaction and send it via RPC
  async function signAndSendTransaction(txSkeleton: helpers.TransactionSkeletonType): Promise<Hash> {
    // Env
    const rpc = new RPC(config.ckbNodeUrl);

    // Sign transaction
    txSkeleton = secp256k1Blake160.prepareSigningEntries(txSkeleton, { config: config.lumos });
    txSkeleton = anyoneCanPay.prepareSigningEntries(txSkeleton, { config: config.lumos });
    txSkeleton = signTransaction(txSkeleton);

    // Convert to Transaction
    const tx = helpers.createTransactionFromSkeleton(txSkeleton);
    console.log(JSON.stringify(tx, null, 2));

    // Send transaction
    return await rpc.sendTransaction(tx, 'passthrough');
  }

  return {
    lock,
    address,
    signMessage,
    signTransaction,
    signAndSendTransaction,
    createAcpLock,
  };
}

function isAcpLockMatches(lock: Script, blake160: Hash, config: SporeConfig): boolean {
  const AnyoneCanPay = config.lumos.SCRIPTS.ANYONE_CAN_PAY!;
  const acpScriptId = {
    codeHash: AnyoneCanPay.CODE_HASH,
    hashType: AnyoneCanPay.HASH_TYPE,
  };

  return isScriptIdEquals(lock, acpScriptId) && lock.args.startsWith(blake160);
}

  const generateAccountFromPrivateKey = (privKey: string): Account => {
    const pubKey = hd.key.privateToPublic(privKey);
    const args = hd.key.publicKeyToBlake160(pubKey);
    const template = config.TESTNET.SCRIPTS["SECP256K1_BLAKE160"]!;
    const lockScript = {
      codeHash: template.CODE_HASH,
      hashType: template.HASH_TYPE,
      args: args,
    };
    const address = helpers.encodeToAddress(lockScript, { config: config.TESTNET });
    return {
      lockScript,
      address,
      pubKey,
    };
  };

  const connectMetaMask = async() => {
    console.log('', publicProvider())

    const { publicClient, webSocketPublicClient } = configureChains(
      [mainnet],
      [publicProvider()],
    );
    const config = createConfig({
      autoConnect: true,
      publicClient,
      webSocketPublicClient,
    });
    const { account } = await connect({ connector: new InjectedConnector() });
    setMetamaskETHAddress(account);
    encodeAddress(account);
  }  

  const connectJoyID = async() => {
    initConfig({network: 'testnet'});
    const authData = await JoyIdConnect();
    const joyidAddress = authData.address;
    const joyidPubKey = authData.pubkey;
    setJoyIDWallet(joyidAddress);
    setJoyIdPubKey(joyidPubKey);
  }

  const encodeAddress = (ethaddress: string) => {
    const lock = commons.omnilock.createOmnilockScript({
      auth: { flag: 'ETHEREUM', content: ethaddress ?? '0x',  },
    }, {config: config.TESTNET});
    const address = helpers.encodeToAddress(lock, {
      config: config.TESTNET
    })
    console.log(address);
    setMetamaskCKBAddress(address);
  }

  const connectSecp256k1 = async () => {
    // const randomWallet = ethers.Wallet.createRandom();
    const privateKey = "0xbe0532a35b4e05026d02315f8c97e752da9f5503c0a9a4b439991b4d2307c9c2";
    const CHARLIE = createSecp256k1Wallet(privateKey, predefinedSporeConfigs.Testnet);
    console.log(CHARLIE.address);
    setSecp256k1Address(CHARLIE.address);
  }

  const createPublicCluster = async () => {
    const privateKey = "0xbe0532a35b4e05026d02315f8c97e752da9f5503c0a9a4b439991b4d2307c9c2";
    const CHARLIE = createSecp256k1Wallet(privateKey, predefinedSporeConfigs.Testnet);
    const CharlieAcpLock = CHARLIE.createAcpLock({
      minCkb: void 0,
    });
    const { txSkeleton, outputIndex } = await createCluster({
      data: {
        name: 'Test acp lock cluster',
        description: 'A public cluster with acp lock',
      },
      fromInfos: [CHARLIE.address],
      toLock: CharlieAcpLock,
      config: predefinedSporeConfigs.Testnet,
    });
    const hash = await CHARLIE.signAndSendTransaction(txSkeleton);
    console.log('CreateAcpCluster transaction sent, hash:', hash);
    console.log('Cluster output index:', outputIndex);

    const clusterCell = txSkeleton.get('outputs').get(outputIndex)!;
    console.log('Cluster ID:', clusterCell.cellOutput.type!.args);
  }

  const createSporeToACPCluster = async () => {
    const privateKey = "0xbe0532a35b4e05026d02315f8c97e752da9f5503c0a9a4b439991b4d2307c9c2";
    const CHARLIE = createSecp256k1Wallet(privateKey, predefinedSporeConfigs.Testnet);
    const { txSkeleton, outputIndex } = await createSpore({
      data: {
        contentType: 'text/plain',
        content: bytifyRawString('Hey Hey Hey, Ma Dong Mei'),
        /**
        * When referencing an ACP public Cluster, even if the Cluster doesn't belong to CHARLIE,
        * CHARLIE can still create Spores that reference the Cluster.
        */
        //0x5179937e46c34385d22d649ca6434025b9e2a66f88cc696be7c365a7e937236b
        //0x4bb8ccd6dc886da947cbe8ac4d51004c9d5335ae1216fda756ac39e4bf665c22
        clusterId: '0x5179937e46c34385d22d649ca6434025b9e2a66f88cc696be7c365a7e937236b',
      },
      toLock: CHARLIE.lock,
      fromInfos: [CHARLIE.address],
      cluster: {
        /**
        * When referencing an ACP public Cluster,
        * you may have to pay at least (10^minCKB) shannons to the Cluster cell as a fee.
        */
        capacityMargin: (clusterCell, margin) => {
          const argsMinCkb = clusterCell.cellOutput.lock.args.slice(42, 2);
          const minCkb = argsMinCkb.length === 2
            ? BI.from(10).pow(number.Uint8.unpack(`0x${argsMinCkb}`))
            : BI.from(0);

          return margin.add(minCkb);
        },
        /**
        * When referencing an ACP public Cluster,
        * the Cluster's corresponding witness should be set to "0x" (empty) and shouldn't be signed.
        */
        updateWitness: '0x',
      },
      config: predefinedSporeConfigs.Testnet,
    });
    const hash = await CHARLIE.signAndSendTransaction(txSkeleton);
    console.log('CreateSporeWithAcpCluster transaction sent, hash:', hash);
    console.log('Spore output index:', outputIndex);

    const sporeCell = txSkeleton.get('outputs').get(outputIndex)!;
    console.log('Spore ID:', sporeCell.cellOutput.type!.args);
  }

  const omnilocksignTransaction = async (
    txSkeleton: helpers.TransactionSkeletonType,
    fromLock: Script,
    signMessage: (message: string) => Promise<string>,
  ): Promise<Transaction> => {
    // config.initializeConfig(config.predefined.AGGRON4);
    const inputs = txSkeleton.get('inputs')!;
    const outputs = txSkeleton.get('outputs')!;

    // add anyone-can-pay minimal capacity in outputs
    // https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0042-omnilock/0042-omnilock.md#anyone-can-pay-mode
    outputs.forEach((output, index) => {
      const { lock } = output.cellOutput;
      if (
        isAnyoneCanPay(lock) &&
        inputs.some((i) => isSameScript(i.cellOutput.lock, lock))
      ) {
        const minimalCapacity = getAnyoneCanPayMinimumCapacity(lock);
        txSkeleton = txSkeleton.update('outputs', (outputs) => {
          output.cellOutput.capacity = BI.from(output.cellOutput.capacity)
            .add(minimalCapacity)
            .toHexString();
          return outputs.set(index, output);
        });
      }
    });

    // remove anyone-can-pay witness when cell lock not changed
    inputs.forEach((input, index) => {
      const { lock } = input.cellOutput;
      if (
        isAnyoneCanPay(lock) &&
        outputs.some((o) => isSameScript(o.cellOutput.lock, lock))
      ) {
        txSkeleton = txSkeleton.update('witnesses', (witnesses) => {
          return witnesses.set(index, '0x');
        });
      }
    });
    let tx = common.prepareSigningEntries(txSkeleton, {
      config: config.TESTNET,
    });

    const signedWitnesses = new Map<string, string>();
    const signingEntries = tx.get('signingEntries')!;
    for (let i = 0; i < signingEntries.size; i += 1) {
      const entry = signingEntries.get(i)!;
      if (entry.type === 'witness_args_lock') {
        const {
          cellOutput: { lock },
        } = inputs.get(entry.index)!;
        // skip anyone-can-pay witness when cell lock not changed
        if (
          !isSameScript(lock, fromLock!) &&
          outputs.some((o) => isSameScript(o.cellOutput.lock, lock))
        ) {
          continue;
        }

        const { message, index } = entry;
        if (signedWitnesses.has(message)) {
          const signedWitness = signedWitnesses.get(message)!;
          tx = tx.update('witnesses', (witnesses) => {
            return witnesses.set(index, signedWitness);
          });
          continue;
        }

        let signature = await signMessage(message);

        // Fix ECDSA recoveryId v parameter
        // https://bitcoin.stackexchange.com/questions/38351/ecdsa-v-r-s-what-is-v
        let v = Number.parseInt(signature.slice(-2), 16);
        if (v >= 27) v -= 27;
        signature = ('0x' +
          signature.slice(2, -2) +
          v.toString(16).padStart(2, '0')) as `0x${string}`;

        const signedWitness = bytes.hexify(
          blockchain.WitnessArgs.pack({
            lock: commons.omnilock.OmnilockWitnessLock.pack({
              signature: bytes.bytify(signature!).buffer,
            }),
          }),
        );
        signedWitnesses.set(message, signedWitness);

        tx = tx.update('witnesses', (witnesses) => {
          return witnesses.set(index, signedWitness);
        });
      }
    }

    const signedTx = helpers.createTransactionFromSkeleton(tx);
    return signedTx;
  }

  const metamaskCreateSpore = async () => {
    // const privateKey = "0xbe0532a35b4e05026d02315f8c97e752da9f5503c0a9a4b439991b4d2307c9c2";
    // const CHARLIE = createSecp256k1Wallet(privateKey, predefinedSporeConfigs.Testnet);
    const { txSkeleton } = await createSpore({
      data: {
        contentType:'text/plain',
        content: bytifyRawString('Hey Hey Hey, Omnilock Ma Dong Mei'),
      },
      fromInfos: [metamaskCKBAddress!!],
      toLock: helpers.parseAddress(metamaskCKBAddress!!, {config: config.TESTNET}),
      config: predefinedSporeConfigs.Testnet,
      capacityMargin: BI.from(0)
    });
    const signedTx = await omnilocksignTransaction(txSkeleton, helpers.parseAddress(metamaskCKBAddress!!, {config: config.TESTNET}), async (message) => {
      const signature = await signMessage({ message: { raw: message } as any })
      return signature;
    });
    const rpc = new RPC(predefinedSporeConfigs.Testnet.ckbNodeUrl);
    const txHash = await rpc.sendTransaction(signedTx, 'passthrough');
    console.log(txHash);
  }

  const createJoyIDSpore = async() => {
    const { txSkeleton } = await createSpore({
      data: {
        contentType:'text/plain',
        content: bytifyRawString('Hey Hey Hey, JoyID Ma Dong Mei'),
      },
      fromInfos: [joyIdWallet!!],
      toLock: helpers.parseAddress(joyIdWallet!!, {config: config.TESTNET}),
      config: predefinedSporeConfigs.Testnet,
      capacityMargin: BI.from(0)
    });
    const tx = helpers.createTransactionFromSkeleton(txSkeleton);
    //@ts-ignore
    const signedTx = await signRawTransaction(tx, joyIdWallet!!)
    const rpc = new RPC(predefinedSporeConfigs.Testnet.ckbNodeUrl);
    const txHash = await rpc.sendTransaction(signedTx, 'passthrough');
    console.log(txHash);
  }

  const connectCCC = async () => {
    // const cccAccount = ccc.Connector();
  }


  return (
    <ccc.Provider>
      <main className="w-full h-full p-10 grid grid-cols-1 md:grid-cols-3 mx-auto gap-4 relative">
        <div className="absolute pointer-events-none inset-0 flex items-center justify-center dark:bg-black bg-black [mask-image:radial-gradient(ellipse_at_center,transparent_20%,black)]"></div>
        {/* <div>Metamask ETH Address: {metamaskETHAddress && metamaskETHAddress}</div>
        <div>Metamask CKB Address: {metamaskCKBAddress && metamaskCKBAddress}</div>
        <div>JoyID CKB Address: {joyIdWallet && joyIdWallet}</div>
        <div onClick={connectMetaMask}>Connect Metamask</div>
        <div onClick={connectJoyID}>Connect JoyID</div> */}
        <div className={cn(
            "z-40 h-60 row-span-1 rounded-xl group/bento hover:shadow-xl transition duration-200 shadow-input dark:shadow-none p-4 dark:bg-black dark:border-white/[0.2] bg-white border border-transparent justify-between flex flex-col space-y-4",
          )}>
              <div className='flex items-center gap-4'>
                <Image
                  src={'/metamask.png'}
                  width={40}
                  height={40}
                  alt={'metamask'}
                />
                <div className="font-extrabold">Metamask</div>
                </div>
                {
                  metamaskETHAddress && 
                  <>
                    <div>
                      <p className='font-light'>ETH Address: {formatString(metamaskETHAddress)}</p>
                      <p className='font-light'>CKB Address: {formatString(metamaskCKBAddress!!)}</p>
                    </div>
                    <button
                      onClick={metamaskCreateSpore} 
                      className="bg-slate-800 no-underline group cursor-pointer relative shadow-2xl shadow-zinc-900 rounded-full p-px text-xs font-semibold leading-6  text-white inline-block">
                      <span className="absolute inset-0 overflow-hidden rounded-full">
                        <span className="absolute inset-0 rounded-full bg-[image:radial-gradient(75%_100%_at_50%_0%,rgba(56,189,248,0.6)_0%,rgba(56,189,248,0)_75%)] opacity-0 transition-opacity duration-500 group-hover:opacity-100"></span>
                      </span>
                      <div className="relative flex space-x-2 items-center z-10 rounded-full bg-zinc-950 py-0.5 px-4 ring-1 ring-white/10 ">
                        <span>{`Create Spore`}</span>
                        <svg
                          width="16"
                          height="16"
                          viewBox="0 0 24 24"
                          fill="none"
                          xmlns="http://www.w3.org/2000/svg"
                        >
                          <path
                            stroke="currentColor"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth="1.5"
                            d="M10.75 8.75L14.25 12L10.75 15.25"
                          ></path>
                        </svg>
                      </div>
                      <span className="absolute -bottom-0 left-[1.125rem] h-px w-[calc(100%-2.25rem)] bg-gradient-to-r from-emerald-400/0 via-emerald-400/90 to-emerald-400/0 transition-opacity duration-500 group-hover:opacity-40"></span>
                    </button>
                  </>
                }
                {
                  !metamaskETHAddress && <div onClick={connectMetaMask}>
                  <button
                    className="bg-slate-800 no-underline group cursor-pointer relative shadow-2xl shadow-zinc-900 rounded-full p-px text-xs font-semibold leading-6  text-white inline-block">
                    <span className="absolute inset-0 overflow-hidden rounded-full">
                      <span className="absolute inset-0 rounded-full bg-[image:radial-gradient(75%_100%_at_50%_0%,rgba(56,189,248,0.6)_0%,rgba(56,189,248,0)_75%)] opacity-0 transition-opacity duration-500 group-hover:opacity-100"></span>
                    </span>
                    <div className="relative flex space-x-2 items-center z-10 rounded-full bg-zinc-950 py-0.5 px-4 ring-1 ring-white/10 ">
                      <span>{`Connect Metamask`}</span>
                      <svg
                        width="16"
                        height="16"
                        viewBox="0 0 24 24"
                        fill="none"
                        xmlns="http://www.w3.org/2000/svg"
                      >
                        <path
                          stroke="currentColor"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth="1.5"
                          d="M10.75 8.75L14.25 12L10.75 15.25"
                        ></path>
                      </svg>
                    </div>
                    <span className="absolute -bottom-0 left-[1.125rem] h-px w-[calc(100%-2.25rem)] bg-gradient-to-r from-emerald-400/0 via-emerald-400/90 to-emerald-400/0 transition-opacity duration-500 group-hover:opacity-40"></span>
                  </button>
                </div>
                }
                
            <div>
          </div>
        </div>
        <div className={cn(
            "z-40 h-60 row-span-1 rounded-xl group/bento hover:shadow-xl transition duration-200 shadow-input dark:shadow-none p-4 dark:bg-black dark:border-white/[0.2] bg-white border border-transparent justify-between flex flex-col space-y-4",
          )}>
              <div className='flex items-center gap-4'>
                <Image
                  src={'/joyid.jpeg'}
                  width={40}
                  height={40}
                  alt={'metamask'}
                />
                <div className="font-extrabold">JoyID</div>
                </div>
                {
                  joyIdWallet && 
                  <>
                    <div>
                      <p className='font-light'>JoyID Address: {formatString(joyIdWallet)}</p>
                    </div>
                    <div className='flex gap-1'>
                      <button 
                        onClick={createJoyIDSpore}
                        className="bg-slate-800 no-underline group cursor-pointer relative shadow-2xl shadow-zinc-900 rounded-full p-px text-xs font-semibold leading-6  text-white inline-block">
                        <span className="absolute inset-0 overflow-hidden rounded-full">
                          <span className="absolute inset-0 rounded-full bg-[image:radial-gradient(75%_100%_at_50%_0%,rgba(56,189,248,0.6)_0%,rgba(56,189,248,0)_75%)] opacity-0 transition-opacity duration-500 group-hover:opacity-100"></span>
                        </span>
                        <div className="relative flex space-x-2 items-center z-10 rounded-full bg-zinc-950 py-0.5 px-4 ring-1 ring-white/10 ">
                          <span>{`Create Spore`}</span>
                          <svg
                            width="16"
                            height="16"
                            viewBox="0 0 24 24"
                            fill="none"
                            xmlns="http://www.w3.org/2000/svg"
                          >
                            <path
                              stroke="currentColor"
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth="1.5"
                              d="M10.75 8.75L14.25 12L10.75 15.25"
                            ></path>
                          </svg>
                        </div>
                        <span className="absolute -bottom-0 left-[1.125rem] h-px w-[calc(100%-2.25rem)] bg-gradient-to-r from-emerald-400/0 via-emerald-400/90 to-emerald-400/0 transition-opacity duration-500 group-hover:opacity-40"></span>
                      </button>
                      <button className="bg-slate-800 no-underline group cursor-pointer relative shadow-2xl shadow-zinc-900 rounded-full p-px text-xs font-semibold leading-6  text-white inline-block">
                        <span className="absolute inset-0 overflow-hidden rounded-full">
                          <span className="absolute inset-0 rounded-full bg-[image:radial-gradient(75%_100%_at_50%_0%,rgba(56,189,248,0.6)_0%,rgba(56,189,248,0)_75%)] opacity-0 transition-opacity duration-500 group-hover:opacity-100"></span>
                        </span>
                        <div className="relative flex space-x-2 items-center z-10 rounded-full bg-zinc-950 py-0.5 px-4 ring-1 ring-white/10 ">
                          <span>{`Create Public Cluster`}</span>
                          <svg
                            width="16"
                            height="16"
                            viewBox="0 0 24 24"
                            fill="none"
                            xmlns="http://www.w3.org/2000/svg"
                          >
                            <path
                              stroke="currentColor"
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth="1.5"
                              d="M10.75 8.75L14.25 12L10.75 15.25"
                            ></path>
                          </svg>
                        </div>
                        <span className="absolute -bottom-0 left-[1.125rem] h-px w-[calc(100%-2.25rem)] bg-gradient-to-r from-emerald-400/0 via-emerald-400/90 to-emerald-400/0 transition-opacity duration-500 group-hover:opacity-40"></span>
                      </button>
                    </div>
                    
                  </>                
                }
                {
                  !joyIdWallet && <div onClick={connectJoyID}>
                  <button className="bg-slate-800 no-underline group cursor-pointer relative shadow-2xl shadow-zinc-900 rounded-full p-px text-xs font-semibold leading-6  text-white inline-block">
                    <span className="absolute inset-0 overflow-hidden rounded-full">
                      <span className="absolute inset-0 rounded-full bg-[image:radial-gradient(75%_100%_at_50%_0%,rgba(56,189,248,0.6)_0%,rgba(56,189,248,0)_75%)] opacity-0 transition-opacity duration-500 group-hover:opacity-100"></span>
                    </span>
                    <div className="relative flex space-x-2 items-center z-10 rounded-full bg-zinc-950 py-0.5 px-4 ring-1 ring-white/10 ">
                      <span>{`Connect JoyID`}</span>
                      <svg
                        width="16"
                        height="16"
                        viewBox="0 0 24 24"
                        fill="none"
                        xmlns="http://www.w3.org/2000/svg"
                      >
                        <path
                          stroke="currentColor"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth="1.5"
                          d="M10.75 8.75L14.25 12L10.75 15.25"
                        ></path>
                      </svg>
                    </div>
                    <span className="absolute -bottom-0 left-[1.125rem] h-px w-[calc(100%-2.25rem)] bg-gradient-to-r from-emerald-400/0 via-emerald-400/90 to-emerald-400/0 transition-opacity duration-500 group-hover:opacity-40"></span>
                  </button>
                </div>
                }
                
            <div>
          </div>
        </div>
        <div className={cn(
            "z-40 h-60 row-span-1 rounded-xl group/bento hover:shadow-xl transition duration-200 shadow-input dark:shadow-none p-4 dark:bg-black dark:border-white/[0.2] bg-white border border-transparent justify-between flex flex-col space-y-4",
          )}>
              <div className='flex items-center gap-4'>
                <Image
                  src={'/secp256k1.webp'}
                  width={40}
                  height={40}
                  alt={'metamask'}
                  className='rounded-full'
                />
                <div className="font-extrabold">Secp256k1</div>
                </div>
                {
                  secp256k1Address && 
                  <>
                    <div>
                      <p className='font-light'>Secp256k1 Address: {formatString(secp256k1Address)}</p>
                    </div>
                    <div className='flex gap-1'>
                      <button
                        onClick={createSporeToACPCluster} 
                        className="bg-slate-800 no-underline group cursor-pointer relative shadow-2xl shadow-zinc-900 rounded-full p-px text-xs font-semibold leading-6  text-white inline-block">
                        <span className="absolute inset-0 overflow-hidden rounded-full">
                          <span className="absolute inset-0 rounded-full bg-[image:radial-gradient(75%_100%_at_50%_0%,rgba(56,189,248,0.6)_0%,rgba(56,189,248,0)_75%)] opacity-0 transition-opacity duration-500 group-hover:opacity-100"></span>
                        </span>
                        <div className="relative flex space-x-2 items-center z-10 rounded-full bg-zinc-950 py-0.5 px-4 ring-1 ring-white/10 ">
                          <span>{`Create Spore`}</span>
                          <svg
                            width="16"
                            height="16"
                            viewBox="0 0 24 24"
                            fill="none"
                            xmlns="http://www.w3.org/2000/svg"
                          >
                            <path
                              stroke="currentColor"
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth="1.5"
                              d="M10.75 8.75L14.25 12L10.75 15.25"
                            ></path>
                          </svg>
                        </div>
                        <span className="absolute -bottom-0 left-[1.125rem] h-px w-[calc(100%-2.25rem)] bg-gradient-to-r from-emerald-400/0 via-emerald-400/90 to-emerald-400/0 transition-opacity duration-500 group-hover:opacity-40"></span>
                      </button>
                      <button
                        onClick={createPublicCluster} 
                        className="bg-slate-800 no-underline group cursor-pointer relative shadow-2xl shadow-zinc-900 rounded-full p-px text-xs font-semibold leading-6  text-white inline-block">
                        <span className="absolute inset-0 overflow-hidden rounded-full">
                          <span className="absolute inset-0 rounded-full bg-[image:radial-gradient(75%_100%_at_50%_0%,rgba(56,189,248,0.6)_0%,rgba(56,189,248,0)_75%)] opacity-0 transition-opacity duration-500 group-hover:opacity-100"></span>
                        </span>
                        <div className="relative flex space-x-2 items-center z-10 rounded-full bg-zinc-950 py-0.5 px-4 ring-1 ring-white/10 ">
                          <span>{`Create Public Cluster`}</span>
                          <svg
                            width="16"
                            height="16"
                            viewBox="0 0 24 24"
                            fill="none"
                            xmlns="http://www.w3.org/2000/svg"
                          >
                            <path
                              stroke="currentColor"
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth="1.5"
                              d="M10.75 8.75L14.25 12L10.75 15.25"
                            ></path>
                          </svg>
                        </div>
                        <span className="absolute -bottom-0 left-[1.125rem] h-px w-[calc(100%-2.25rem)] bg-gradient-to-r from-emerald-400/0 via-emerald-400/90 to-emerald-400/0 transition-opacity duration-500 group-hover:opacity-40"></span>
                      </button>
                    </div>
                  </>
                }
                {
                  !secp256k1Address && <div onClick={connectSecp256k1}>
                  <button className="bg-slate-800 no-underline group cursor-pointer relative shadow-2xl shadow-zinc-900 rounded-full p-px text-xs font-semibold leading-6  text-white inline-block">
                    <span className="absolute inset-0 overflow-hidden rounded-full">
                      <span className="absolute inset-0 rounded-full bg-[image:radial-gradient(75%_100%_at_50%_0%,rgba(56,189,248,0.6)_0%,rgba(56,189,248,0)_75%)] opacity-0 transition-opacity duration-500 group-hover:opacity-100"></span>
                    </span>
                    <div className="relative flex space-x-2 items-center z-10 rounded-full bg-zinc-950 py-0.5 px-4 ring-1 ring-white/10 ">
                      <span>{`Connect Secp256K1`}</span>
                      <svg
                        width="16"
                        height="16"
                        viewBox="0 0 24 24"
                        fill="none"
                        xmlns="http://www.w3.org/2000/svg"
                      >
                        <path
                          stroke="currentColor"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth="1.5"
                          d="M10.75 8.75L14.25 12L10.75 15.25"
                        ></path>
                      </svg>
                    </div>
                    <span className="absolute -bottom-0 left-[1.125rem] h-px w-[calc(100%-2.25rem)] bg-gradient-to-r from-emerald-400/0 via-emerald-400/90 to-emerald-400/0 transition-opacity duration-500 group-hover:opacity-40"></span>
                  </button>
                </div>
                }        
            <div>
          </div>
        </div>
        <div className={cn(
            "z-40 h-60 row-span-1 rounded-xl group/bento hover:shadow-xl transition duration-200 shadow-input dark:shadow-none p-4 dark:bg-black dark:border-white/[0.2] bg-white border border-transparent justify-between flex flex-col space-y-4",
          )}>
              <div className='flex items-center gap-4'>
                <Image
                  src={'/ccc.webp'}
                  width={40}
                  height={40}
                  alt={'metamask'}
                  className='rounded-full'
                />
                <div className="font-extrabold">CCC</div>
                </div>
                {
                  secp256k1Address && 
                  <>
                    <div>
                      <p className='font-light'>Secp256k1 Address: {formatString(secp256k1Address)}</p>
                    </div>
                    <div className='flex gap-1'>
                      <button
                        onClick={createSporeToACPCluster} 
                        className="bg-slate-800 no-underline group cursor-pointer relative shadow-2xl shadow-zinc-900 rounded-full p-px text-xs font-semibold leading-6  text-white inline-block">
                        <span className="absolute inset-0 overflow-hidden rounded-full">
                          <span className="absolute inset-0 rounded-full bg-[image:radial-gradient(75%_100%_at_50%_0%,rgba(56,189,248,0.6)_0%,rgba(56,189,248,0)_75%)] opacity-0 transition-opacity duration-500 group-hover:opacity-100"></span>
                        </span>
                        <div className="relative flex space-x-2 items-center z-10 rounded-full bg-zinc-950 py-0.5 px-4 ring-1 ring-white/10 ">
                          <span>{`Create Spore`}</span>
                          <svg
                            width="16"
                            height="16"
                            viewBox="0 0 24 24"
                            fill="none"
                            xmlns="http://www.w3.org/2000/svg"
                          >
                            <path
                              stroke="currentColor"
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth="1.5"
                              d="M10.75 8.75L14.25 12L10.75 15.25"
                            ></path>
                          </svg>
                        </div>
                        <span className="absolute -bottom-0 left-[1.125rem] h-px w-[calc(100%-2.25rem)] bg-gradient-to-r from-emerald-400/0 via-emerald-400/90 to-emerald-400/0 transition-opacity duration-500 group-hover:opacity-40"></span>
                      </button>
                      <button
                        onClick={createPublicCluster} 
                        className="bg-slate-800 no-underline group cursor-pointer relative shadow-2xl shadow-zinc-900 rounded-full p-px text-xs font-semibold leading-6  text-white inline-block">
                        <span className="absolute inset-0 overflow-hidden rounded-full">
                          <span className="absolute inset-0 rounded-full bg-[image:radial-gradient(75%_100%_at_50%_0%,rgba(56,189,248,0.6)_0%,rgba(56,189,248,0)_75%)] opacity-0 transition-opacity duration-500 group-hover:opacity-100"></span>
                        </span>
                        <div className="relative flex space-x-2 items-center z-10 rounded-full bg-zinc-950 py-0.5 px-4 ring-1 ring-white/10 ">
                          <span>{`Create Public Cluster`}</span>
                          <svg
                            width="16"
                            height="16"
                            viewBox="0 0 24 24"
                            fill="none"
                            xmlns="http://www.w3.org/2000/svg"
                          >
                            <path
                              stroke="currentColor"
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth="1.5"
                              d="M10.75 8.75L14.25 12L10.75 15.25"
                            ></path>
                          </svg>
                        </div>
                        <span className="absolute -bottom-0 left-[1.125rem] h-px w-[calc(100%-2.25rem)] bg-gradient-to-r from-emerald-400/0 via-emerald-400/90 to-emerald-400/0 transition-opacity duration-500 group-hover:opacity-40"></span>
                      </button>
                    </div>
                  </>
                }
                {
                  !secp256k1Address && <div onClick={open}>
                  <button className="bg-slate-800 no-underline group cursor-pointer relative shadow-2xl shadow-zinc-900 rounded-full p-px text-xs font-semibold leading-6  text-white inline-block">
                    <span className="absolute inset-0 overflow-hidden rounded-full">
                      <span className="absolute inset-0 rounded-full bg-[image:radial-gradient(75%_100%_at_50%_0%,rgba(56,189,248,0.6)_0%,rgba(56,189,248,0)_75%)] opacity-0 transition-opacity duration-500 group-hover:opacity-100"></span>
                    </span>
                    <div className="relative flex space-x-2 items-center z-10 rounded-full bg-zinc-950 py-0.5 px-4 ring-1 ring-white/10 ">
                      <span>{`Connect CCC`}</span>
                      <svg
                        width="16"
                        height="16"
                        viewBox="0 0 24 24"
                        fill="none"
                        xmlns="http://www.w3.org/2000/svg"
                      >
                        <path
                          stroke="currentColor"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth="1.5"
                          d="M10.75 8.75L14.25 12L10.75 15.25"
                        ></path>
                      </svg>
                    </div>
                    <span className="absolute -bottom-0 left-[1.125rem] h-px w-[calc(100%-2.25rem)] bg-gradient-to-r from-emerald-400/0 via-emerald-400/90 to-emerald-400/0 transition-opacity duration-500 group-hover:opacity-40"></span>
                  </button>
                </div>
                }        
            <div>
          </div>
        </div>
      </main>
    </ccc.Provider>
  );
}

