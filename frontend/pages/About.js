import React from "react";



import AboutUs from "../components/sections/AboutUs";
import AboutUsLayout from "../components/layouts/AboutUsLayout";


export default function About({ isSignedIn, wallet ,contractId}) {
  return (
    <AboutUsLayout isSignedIn={isSignedIn} wallet={wallet}>
        <AboutUs isSignedIn={isSignedIn} wallet={wallet} contractId={contractId}/>
    </AboutUsLayout>
  );
}