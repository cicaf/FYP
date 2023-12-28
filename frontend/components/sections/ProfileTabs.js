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
} from '@chakra-ui/react';
import { MdLocalShipping } from 'react-icons/md';
import * as nearAPI from "near-api-js";
// import { Link } from "react-router-dom";
import Select from 'react-select';
import { uploadToIPFS } from "~/Infura";
import { utils } from 'near-api-js';

export default function ProfileTabs({ isSignedIn, wallet ,contractId}) {

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
  const [user, setUser] = useState("");

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
          getUser().then(setUser);

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

  async function getUser() {
    try {
      if (isSignedIn) {
        const account_id = wallet.accountId;
        const result = await wallet.viewMethod({ method: "get_user", args: { account_id: account_id }, contractId });
        return result;
      } else {
        return "";
      }
    } catch (error) {
      console.error("Error fetching saver:", error);
      return ""; // Return an empty string or handle the error accordingly
    }
  }
  


  console.log("user is",user);


  return (
    <Container maxW={'7xl'}>
    <>
      {user === null || !user ? (
        <HStack alignSelf={'end'} marginBottom={2}>
          <Button onClick={() => openModal('signup')} background={'green'} color={'white'}>
            Update Details
          </Button>
        </HStack>
      ) : (
        <>
        <p> Welcome <span style={{color:"green"}}>{user.first_name}</span></p>

        <SimpleGrid
        columns={{ base: 1, lg: 2 }}
        spacing={{ base: 8, md: 10 }}
        py={{ base: 18, md: 24 }}>
        <Stack spacing={{ base: 6, md: 10 }}>
          <Box as={'header'}>
            <Heading
              lineHeight={1.1}
              fontWeight={600}
              fontSize={{ base: '2xl', sm: '4xl', lg: '5xl' }}>
              {user.account}
            </Heading>
            <Text
              color={useColorModeValue('gray.900', 'gray.400')}
              fontWeight={300}
              fontSize={'2xl'}>
               {(bal.available/near).toFixed(5)}  NEAR
            </Text>
          </Box>

          <Stack
            spacing={{ base: 4, sm: 6 }}
            direction={'column'}
            divider={
              <StackDivider borderColor={useColorModeValue('gray.200', 'gray.600')} />
            }>
            <VStack spacing={{ base: 4, sm: 6 }}>
              <Text fontSize={'lg'}>
                {user.about_yourself}
              </Text>
            </VStack>
            <Box>
              <Text
                fontSize={{ base: '16px', lg: '18px' }}
                color={useColorModeValue('yellow.500', 'yellow.300')}
                fontWeight={'500'}
                textTransform={'uppercase'}
                mb={'4'}>
                Contacts
              </Text>

              <SimpleGrid columns={{ base: 1, md: 2 }} spacing={10}>
                <List spacing={2}>
                  <ListItem>{user.first_name} {user.last_name}</ListItem>
                  <ListItem>{user.phone_number}</ListItem>{' '}
                  <ListItem>{user.email}</ListItem>
                </List>

              </SimpleGrid>
            </Box>

          </Stack>

        </Stack>
      </SimpleGrid>
        </>
        
      )}
    </>
      <>
      
      <AlertDialog isOpen={alertOpen} onClose={closeAlert}>
        <AlertDialogOverlay />
        <AlertDialogContent>
          <AlertDialogHeader>Error!</AlertDialogHeader>
          <AlertDialogBody color={'orange'}>
            Email not found in the system
          </AlertDialogBody>
          <AlertDialogFooter>
            <Button colorScheme="blue" onClick={closeAlert}>
              Close
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <Modal
        isOpen={listingModalOpen && currentModal === 'signup'}
        onClose={closeModal}
        initialFocusRef={initialRef}
        finalFocusRef={finalRef}
      >
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>Add Listing</ModalHeader>
          <ModalCloseButton />
          <ModalBody pb={6}>
          <HStack>
              <Box>
              <FormControl mt={4}>
                <FormLabel>First Name</FormLabel>
                  <Input
                    type="text"
                    name="first_name"
                    placeholder="Enter first name"
                    value={formData.first_name}
                    onChange={handleInputChange}
                  />
              </FormControl>
              </Box>
              <Box>
                <FormControl mt={4}>
                  <FormLabel>Last Name</FormLabel>
                    <Input
                      type="text"
                      name="last_name"
                      placeholder="Enter Last Name"
                      value={formData.username}
                      onChange={handleInputChange}
                    />
                </FormControl>
              </Box>
            </HStack>

            <FormControl mt={4}>
              <FormLabel>About Yourself</FormLabel>
              <Textarea
                name="about_yourself"
                placeholder="Tell us about yourself"
                value={formData.about_yourself}
                onChange={handleInputChange}
                size="sm"
              />
            </FormControl>

            <HStack>
              <Box>
              <FormControl mt={4}>
              <FormLabel>Phone Number</FormLabel>
              <Input
                type="text"
                name="phone_number"
                placeholder="Enter valid phone number"
                value={formData.phone_number}
                onChange={handleInputChange}

              />
            </FormControl>
              </Box>
              <Box>
                <FormControl mt={4}>
                  <FormLabel>Email</FormLabel>
                    <Input
                      type="email"
                      name="email"
                      placeholder="Enter mail"
                      value={formData.email}
                      onChange={handleInputChange}
                    />
                </FormControl>
              </Box>
            </HStack>
            <HStack>
              <Box>
              <FormControl mt={4}>
              <FormLabel>Address</FormLabel>
              <Input
                type="text"
                name="address"
                placeholder="Enter adress"
                value={formData.address}
                onChange={handleInputChange}
              />
            </FormControl>
              </Box>
            </HStack>

            <FormControl mt={4}>
              <FormLabel>Password</FormLabel>
              <Input
                type="password"
                name="password"
                placeholder="Enter password"
                value={formData.password}
                onChange={handleInputChange}
                size="sm"
              />
            </FormControl>

          </ModalBody>
          <ModalFooter>
            <Button colorScheme="blue" mr={3} onClick={handleSubmit}>
              Post
            </Button>
            <Button onClick={closeModal}>Cancel</Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
      </>
      <>


                  </>
    </Container>
  );
}
