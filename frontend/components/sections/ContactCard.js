'use client'

import React,{useEffect,useState} from 'react'
import { 
  Stack,
  Text,
  Button,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  useDisclosure,
  FormControl,
  FormLabel,
  Input,
  Textarea,
  Box,

 } from '@chakra-ui/react'
import { FcLock } from 'react-icons/fc'
import { Link } from "react-router-dom";
import Select from 'react-select';
import { uploadToIPFS } from "~/Infura";
import { utils } from 'near-api-js';

export default function ContactCard({ isSignedIn, wallet ,contractId}) {
  



  return (
    <>


    </>
  )
}