import React from "react";


import BuyerLayout from "../components/layouts/BuyerLayout";
import BuyerList from "../components/sections/BuyerList";


export default function Buyer({ isSignedIn, wallet , contractId}) {
  return (
    <BuyerLayout isSignedIn={isSignedIn} wallet={wallet}>
        <BuyerList isSignedIn={isSignedIn} wallet={wallet} contractId={contractId}/>
    </BuyerLayout>
  );
}