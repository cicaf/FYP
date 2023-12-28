import React from "react";

import Hero from "../components/sections/Hero";
import LandingLayout from "../components/layouts/LandingLayout";
import SplitWithImage from "../components/sections/features";
import CryptoFreelancerWebsite from "../components/sections/NearFeatures";
import CryptoFreelancerTestimonials from "../components/sections/Testimonials";
import BasicStatistics from "../components/sections/Stats";


export default function Landing({ isSignedIn, wallet }) {
  return (
    <LandingLayout isSignedIn={isSignedIn} wallet={wallet}>
      <Hero
        title="From Freelancer to Cryptopreneur
        Your Journey Starts Here."
        subtitle="Welcome to the world of crypto freelancing!
        Whether you're a developer, designer, writer,
        or marketer, the crypto space
        offers exciting opportunities to leverage your
        skills and earn. in cryptocurrencies."
        image="https://source.unsplash.com/collection/IzTMqF_RipM/800x600"
        ctaText="Find Job"
        ctaLink="/signup"
      />

      <SplitWithImage />
      <CryptoFreelancerWebsite />
      <CryptoFreelancerTestimonials />
      <BasicStatistics />
      

    </LandingLayout>
  );
}
