import 'regenerator-runtime/runtime';
import { Wallet } from './near-wallet';

// const CONTRACT_ADDRESS = process.env.CONTRACT_NAME;
const CONTRACT_ADDRESS ="dev-1699006645642-96863308071582";

// When creating the wallet you can optionally ask to create an access key
// Having the key enables to call non-payable methods without interrupting the user to sign
const wallet = new Wallet({ createAccessKeyFor: CONTRACT_ADDRESS })


const signInButton  = document.getElementById("sign-in-button");
const signOutButton  = document.getElementById("sign-out-button");
const dashboardButton  = document.getElementById("dashboard_button");


if(signInButton !=null){
    signInButton.addEventListener('click', ()=>{
        wallet.signIn();
    });
}

if(signOutButton != null) {
    signOutButton.addEventListener('click', () => {
        wallet.signOut();
    });
}

// Setup on page load
window.onload = async () => {
    let isSignedIn = await wallet.startUp();

    if (isSignedIn) {
        console.log("signed in ..."+ window.location.pathname)
        signedInFlow();
    } else {
        console.log("signed out flow ...")

        signedOutFlow();
    }

    // samart contract call
    fetchGreeting();
};

// Button clicks
// document.querySelector('#sign-in-button').onclick = () => { wallet.signIn(); };
// document.querySelector('#sign-out-button').onclick = () => { wallet.signOut(); };

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

// Get greeting from the contract on chain
async function fetchGreeting() {
    const currentGreeting = await wallet.viewMethod({ method: 'get_greeting', contractId: CONTRACT_ADDRESS });

    console.log("Greeting res "+ currentGreeting);


    const setGreeting = await wallet.callMethod({method: 'set_greeting', contractId: CONTRACT_ADDRESS, args: { "greeting": "Hulabaloo.." }})

    console.log("setGreeting Greeting res "+ JSON.stringify(setGreeting));


    const currentGreeting2 = await wallet.viewMethod({ method: 'get_greeting', contractId: CONTRACT_ADDRESS });

    console.log("currentGreeting2 Greeting res "+ currentGreeting2);
    // document.querySelectorAll('[data-behavior=greeting]').forEach(el => {
    //     el.innerText = currentGreeting;
    //     el.value = currentGreeting;
    // });
}

// Display the signed-out-flow container
function signedOutFlow() {
    console.log("sign out.....");
    if(dashboardButton!=null) {
        dashboardButton.style.display = 'none'
    }
}

// Displaying the signed in flow container and fill in account-specific data
function signedInFlow() {
    if(signInButton!=null) {
        signInButton.style.display = 'none';
    }
}

