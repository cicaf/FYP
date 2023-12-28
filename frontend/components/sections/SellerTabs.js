import React, { useEffect, useState } from 'react';

import {
  Box,
  chakra,
  Container,
  Stack,
  Text,
  Image,
  Flex,
  VStack, // Import VStack for vertical stacking
  Button,
  Heading,
  SimpleGrid,
  StackDivider,
  useColorModeValue,
  VisuallyHidden,
  List,
  ListItem,
  Tabs,
  TabList, 
  TabPanels,
  Tab,
  TabPanel,
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
  Divider,
  HStack,
  Tag,
  Wrap,
  WrapItem,
  SpaceProps,
  Link,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  AlertDialog, AlertDialogOverlay, AlertDialogContent, AlertDialogHeader, AlertDialogBody, AlertDialogFooter,
  Table,
  Thead,
  Tbody,
  Tfoot,
  Tr,
  Th,
  Td,
  TableCaption,
  TableContainer,
  Badge,
} from '@chakra-ui/react';
import { MdLocalShipping } from 'react-icons/md';
import * as nearAPI from "near-api-js";
// import { Link } from "react-router-dom";
import Select from 'react-select';
import { uploadToIPFS } from "~/Infura";
import { utils } from 'near-api-js';

export default function SellerTabs({ isSignedIn, wallet ,contractId}) {

  const { isOpen: listingModalOpen, onOpen: openListingModal, onClose: closeListingModal } = useDisclosure();
  const { isOpen: transferModalOpen, onOpen: openTransferModal, onClose: closeTransferModal } = useDisclosure();
  const { isOpen: alertOpen, onOpen: openAlert, onClose: closeAlert } = useDisclosure();

  const [currentModal, setCurrentModal] = React.useState(null);

  const initialRef = React.useRef(null);
  const finalRef = React.useRef(null);

  const openModal = (modal) => {
    setCurrentModal(modal);
    if (modal === 'signup') {
      openListingModal();
    } 
  };

  const closeModal = () => {
    if (currentModal === 'signup') {
      closeListingModal();
    } 
    setCurrentModal(null);
  };

  console.log(wallet.walletSelector.options.network);
  const [freelancer,setFreelancer] = useState();
  const [portfolios,setPortfolios] = useState([]);
  const [experiences,setExperiences] = useState([]);
  const [bal, setBalance] = useState("");
  const [properties, setProperties] = useState([]);

  const { keyStores } = nearAPI;
  const { connect } = nearAPI;
  const myKeyStore = new keyStores.BrowserLocalStorageKeyStore();
  const [uiPleaseWait, setUiPleaseWait] = useState(true);



  const connectionConfig = {

    networkId: "testnet",
    keyStore: myKeyStore,
    nodeUrl: "https://rpc.testnet.near.org",
    walletUrl: "https://wallet.testnet.near.org",
    helperUrl: "https://helper.testnet.near.org",
    explorerUrl: "https://explorer.testnet.near.org",
  };


  
  const near = "1000000000000000000000000";


  // first_name: String, 
  // last_name: String, 
  // about_yourself: String, 
  // phone_number: String, 
  // address: String, 
  // email: String, 
  // password: String

    const [formData, setFormData] = useState({
      first_name: '',
      last_name: '',
      about_yourself: '',
      phone_number: '',
      address:'',
      email:'',
      password: '',

    });



    const [formData1, setFormData1] = useState({
      email:'',
      password:'',
    });


    const handleInputChange = (e) => {
      const { name, value } = e.target;
      setFormData({ ...formData, [name]: value });
    };

    const handleInputChange1 = (e) => {
      const { name, value } = e.target;
      setFormData1({ ...formData1, [name]: value });
    };
  



  useEffect(() => {
    // Function to perform the async action
    async function handleAccount() {
      try {
        // Check if the user is signed in
        if (isSignedIn) {
          // Perform the asynchronous action
          const nearConnection = await connect(connectionConfig);
          const account = await nearConnection.account(wallet.accountId);
          const balance = await account.getAccountBalance();
          setBalance(balance);
          getPropertiesAccount().then(setProperties);

        } else {
          console.log('User is not signed in.');
        }
      } catch (error) {
        // Handle any errors here
        console.error('Error performing async action:', error);
      }
    }

    // Call the function to handle the async action
    handleAccount();
  }, [isSignedIn,wallet]);




  const handleSubmit = async () => {


  const first_name = formData.first_name;
  const  last_name = formData.last_name;
  const about_yourself = formData.about_yourself;
  const phone_number= formData.phone_number;
  const  email = formData.email;
  const password = formData.password;
  const address = formData.address;

        wallet
        .callMethod({
        method: "add_user",
        args: {
            first_name: first_name, 
            last_name: last_name, 
            about_yourself: about_yourself, 
            phone_number: phone_number, 
            address: address, 
            email: email, 
            password: password
        },
        contractId:contractId
        })
        .then(async () => {
           
        })
        .then(setUser)
        .finally(() => {
        setUiPleaseWait(false);
        });
      

        closeModal() // Close the modal after posting the job
  };

  async function getPropertiesAccount() {
    try {
      if (isSignedIn) {
        const account_id = wallet.accountId;
        const result = await wallet.viewMethod({ method: "get_properties_for_account", args: { account_id: account_id }, contractId });
        return result;
      } else {
        return "";
      }
    } catch (error) {
      console.error("Error fetching saver:", error);
      return ""; // Return an empty string or handle the error accordingly
    }
  }
  


  console.log("user is",properties);


  return (
    <Container maxW={'7xl'}>
        <Badge>My properties</Badge>
        <TableContainer>
            <Table variant='simple' size="sm" borderWidth="1px">
                <TableCaption>All properties</TableCaption>
                <Thead>
                <Tr>
                    <Th>ID</Th>
                    <Th>Owner</Th>
                    <Th>Title</Th>
                    <Th>Description</Th>
                    <Th>Status</Th>
                    <Th>Price</Th>
                    <Th>Area</Th>
                    <Th>Contact Name</Th>
                    <Th>Username</Th>
                    <Th>Email</Th>
                    <Th>Phone</Th>
                    <Th>Address</Th>
                    <Th>City</Th>
                    <Th>State</Th>
                    <Th>County</Th>
                    <Th>Latitude</Th>
                    <Th>Longitude</Th>
                </Tr>
                </Thead>
                <Tbody>
                {properties.map((property, index) => (
                    <Tr key={index}>
                    <Td>{property.id}</Td>
                    <Td>{property.owner}</Td>
                    <Td>{property.title}</Td>
                    <Td>{property.description}</Td>
                    <Td>{property.status}</Td>
                    <Td>{property.price}</Td>
                    <Td>{property.area}</Td>
                    <Td>{property.contact_information.name}</Td>
                    <Td>{property.contact_information.username}</Td>
                    <Td>{property.contact_information.email}</Td>
                    <Td>{property.contact_information.phone}</Td>
                    <Td>{property.location.address}</Td>
                    <Td>{property.location.city}</Td>
                    <Td>{property.location.state}</Td>
                    <Td>{property.location.county}</Td>
                    <Td>{property.location.lat}</Td>
                    <Td>{property.location.long}</Td>
                    </Tr>
                ))}
                </Tbody>
            </Table>
            </TableContainer>
    </Container>
  );
}
