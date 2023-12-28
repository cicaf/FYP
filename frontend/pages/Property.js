import React from "react";



import PropertyLayout from "../components/layouts/PropertyLayout";
import PropertyList from "../components/sections/PropertyList";


export default function Property({ isSignedIn, wallet , contractId}) {
  return (
    <PropertyLayout isSignedIn={isSignedIn} wallet={wallet}>
        <PropertyList isSignedIn={isSignedIn} wallet={wallet} contractId={contractId}/>
    </PropertyLayout>
  );
}