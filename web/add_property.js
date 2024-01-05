/* A helper file that simplifies using the wallet selector */

// near api js
import { providers } from 'near-api-js';

// wallet selector UI
// import '@near-wallet-selector/modal-ui/styles.css';
// import { setupModal } from '@near-wallet-selector/modal-ui';
// import LedgerIconUrl from '@near-wallet-selector/ledger/assets/ledger-icon.png';
// import MyNearIconUrl from '@near-wallet-selector/my-near-wallet/assets/my-near-wallet-icon.png';

// wallet selector options
// import { setupWalletSelector } from '@near-wallet-selector/core';
// import { setupLedger } from '@near-wallet-selector/ledger';
// import { setupMyNearWallet } from '@near-wallet-selector/my-near-wallet';

const THIRTY_TGAS = '30000000000000';
const NO_DEPOSIT = '0';

// Wallet that simplifies using the wallet selector
export class Wallet {
  walletSelector;
  wallet;
  network;
  createAccessKeyFor;

  constructor({ createAccessKeyFor = undefined, network = 'testnet' }) {
    // Login to a wallet passing a contractId will create a local
    // key, so the user skips signing non-payable transactions.
    // Omitting the accountId will result in the user being
    // asked to sign all transactions.
    this.createAccessKeyFor = createAccessKeyFor
    this.network = network
  }

  // To be called when the website loads
  //   async startUp() {
  //     this.walletSelector = await setupWalletSelector({
  //       network: this.network,
  //       modules: [setupMyNearWallet({ iconUrl: MyNearIconUrl }),
  //       setupLedger({ iconUrl: LedgerIconUrl })],
  //     });

  //     const isSignedIn = this.walletSelector.isSignedIn();

  //     if (isSignedIn) {
  //       this.wallet = await this.walletSelector.wallet();
  //       this.accountId = this.walletSelector.store.getState().accounts[0].accountId;
  //     }

  //     return isSignedIn;
  //   }

  // Sign-in method
  signIn() {
    const description = 'Please select a wallet to sign in.';
    const modal = setupModal(this.walletSelector, { contractId: this.createAccessKeyFor, description });
    modal.show();
  }

  // Sign-out method
  signOut() {
    this.wallet.signOut();
    this.wallet = this.accountId = this.createAccessKeyFor = null;
    window.location.replace(window.location.origin + window.location.pathname);
  }

  // Make a read-only call to retrieve information from the network
  async viewMethod({ contractId, method, args = {} }) {
    const { network } = this.walletSelector.options;
    const provider = new providers.JsonRpcProvider({ url: network.nodeUrl });

    let res = await provider.query({
      request_type: 'call_function',
      account_id: contractId,
      method_name: method,
      args_base64: Buffer.from(JSON.stringify(args)).toString('base64'),
      finality: 'optimistic',
    });
    return JSON.parse(Buffer.from(res.result).toString());
  }

  // Get transaction result from the network
  async getTransactionResult(txhash) {
    const { network } = this.walletSelector.options;
    const provider = new providers.JsonRpcProvider({ url: network.nodeUrl });

    // Retrieve transaction result from the network
    const transaction = await provider.txStatus(txhash, 'unnused');
    return providers.getTransactionLastResult(transaction);
  }
}
const CONTRACT_ADDRESS = "dev-1699006645642-96863308071582"





// When creating the wallet you can optionally ask to create an access key
// Having the key enables to call non-payable methods without interrupting the user to sign
const wallet = new Wallet({ createAccessKeyFor: CONTRACT_ADDRESS })

// Setup on page load
window.onload = async () => {
  let isSignedIn = await wallet.startUp();

  if (isSignedIn) {
    signedInFlow();
  } else {
    signedOutFlow();
  }

  fetchGreeting();
};

// Button clicks
document.querySelector('form').onsubmit = doUserAction;
document.querySelector('#sign-in-button').onclick = () => { wallet.signIn(); };
document.querySelector('#sign-out-button').onclick = () => { wallet.signOut(); };

// Take the new greeting and send it to the contract
async function doUserAction(event) {
  event.preventDefault();
  const { greeting } = event.target.elements;

  document.querySelector('#signed-in-flow main')
    .classList.add('please-wait');

  await wallet.callMethod({ method: 'set_greeting', args: { greeting: greeting.value }, contractId: CONTRACT_ADDRESS });

  // ===== Fetch the data from the blockchain =====
  await fetchGreeting();
  document.querySelector('#signed-in-flow main')
    .classList.remove('please-wait');
}



document.querySelector('#add-property-button').onclick = addProperty;

async function addProperty() {
  try {
    const isAvailable = document.getElementById('is_available').checked;
    const title = document.getElementById('title').value;
    // Retrieve other input values similarly for description, status, price, etc.

    const result = await wallet.viewMethod({
      method: 'add_property',
      contractId: CONTRACT_ADDRESS,
      args: {
        is_available: true, // bool value for is_available
        title: "Sample Title", // String value for title
        description: "Sample Description", // String value for description
        status: "Sample Status", // String value for status
        price: 100, // i32 value for price
        area: 200, // i32 value for area
        name: "John Doe", // String value for name
        username: "johndoe123", // String value for username
        email: "johndoe@example.com", // String value for email
        phone: "1234567890", // String value for phone
        address: "Sample Address", // String value for address
        city: "Sample City", // String value for city
        state: "Sample State", // String value for state
        county: "Sample County", // String value for county
        lat: 123.45, // f32 value for lat
        long: 67.89 // f32 value for long
      },
      gas: THIRTY_TGAS,
      deposit: NO_DEPOSIT
    });

    console.log("call result", result);

    await fetchUpdatedData(); // Update UI or fetch new data upon success
  } catch (error) {
    console.error('Error:', error);
  }
}
