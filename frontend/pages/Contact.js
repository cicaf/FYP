import React from "react";


import ContactsLayout from "../components/layouts/ContactsLayout";
import ContactCard from "../components/sections/ContactCard";


export default function Contact({ isSignedIn, wallet , contractId}) {
  return (
    <ContactsLayout isSignedIn={isSignedIn} wallet={wallet} contractId={contractId}>
        <ContactCard isSignedIn={isSignedIn} wallet={wallet} contractId={contractId}/>
    </ContactsLayout>
  );
}