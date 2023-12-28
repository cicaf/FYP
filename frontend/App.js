import 'regenerator-runtime/runtime';
import React from 'react';
import './assets/global.css';
import {Route,Routes} from 'react-router-dom'
import Landing from "./pages/Landing";
import FooterCrypto from "./components/sections/Footer"
import Profile from './pages/Profile';
import Contact from "./pages/Contact";
import About from "./pages/About"
import Property from './pages/Property';
import Buyer from './pages/Buyer';
import Seller from './pages/Seller';




export default function App({ isSignedIn, contractId, wallet }) {
  const [valueFromBlockchain, setValueFromBlockchain] = React.useState();

  const [uiPleaseWait, setUiPleaseWait] = React.useState(true);

  return (
    <>
      <div className='container'>

        <Routes>
          {/* <Route path="/" element = {<Home />} /> */}
          <Route path="/" element = {<Landing isSignedIn={isSignedIn} wallet={wallet}/>} />
          <Route path="/profile" element = {<Profile isSignedIn={isSignedIn} wallet={wallet} contractId={contractId}/>} />
          <Route path="/properties" element = {<Property isSignedIn={isSignedIn} wallet={wallet} contractId={contractId}/>} />
          <Route path="/buyer" element = {<Buyer isSignedIn={isSignedIn} wallet={wallet} contractId={contractId}/>} />
          <Route path="/contacts" element = {<Contact isSignedIn={isSignedIn} wallet={wallet} contractId={contractId}/>} />
          <Route path="/aboutus" element = {<About isSignedIn={isSignedIn} wallet={wallet} contractId={contractId}/>} />
          <Route path="/seller" element = {<Seller isSignedIn={isSignedIn} wallet={wallet} contractId={contractId}/>} />
        
        </Routes>

      </div>
      <FooterCrypto />

    </>
  );
}