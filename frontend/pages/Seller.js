import React from "react";



import SellerLayout from "../components/layouts/SellerLayout";
import SellerTabs from "../components/sections/SellerTabs";


export default function Seller({ isSignedIn, wallet ,contractId}) {
  return (
    <SellerLayout isSignedIn={isSignedIn} wallet={wallet}>
        <SellerTabs isSignedIn={isSignedIn} wallet={wallet} contractId={contractId}/>
    </SellerLayout>
  );
}