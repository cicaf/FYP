import React, { useState, useEffect } from 'react';
import {
  Box,
  Heading,
  Badge,
  Image,
  Button,
  Divider,
  Text,
  Divider,
  HStack,
  Tag,
  Wrap,
  WrapItem,
  useColorModeValue,
  Container,
  VStack,
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
  Popover,
  PopoverTrigger,
  PopoverContent,
  PopoverHeader,
  PopoverBody,
  PopoverFooter,
  PopoverArrow,
  PopoverCloseButton,
  PopoverAnchor,
  Divider
} from '@chakra-ui/react';

import { Link } from "react-router-dom";
import Select from 'react-select';
import { uploadToIPFS } from "~/Infura";
import { utils } from 'near-api-js';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';

function generateTo(JobId) {
  return {
    pathname: `/job/${JobId}`,
  };
}



function PropertyTags(props) {
  const { marginTop = 0, tags } = props;

  const tagElements = tags.map((tag) => {
    return (
      <Tag size={'md'} variant="solid" colorScheme="orange" key={tag}>
        {tag}
      </Tag>
    );
  });

  return <HStack spacing={2} marginTop={marginTop}>{tagElements}</HStack>;
}

const linkStyle = {
  textDecoration: 'none', // Remove underline
  color: 'blue', // Change the text color to blue
  // Add any other styles you want here
};

function ProprtyOwner(props) {
  return (
    <HStack marginTop="2" spacing="2" display="flex" alignItems="center">
      <Image
        borderRadius="full"
        boxSize="40px"
        src="https://res.cloudinary.com/dufdzujik/image/upload/v1697103579/FUN_FOOD/user_1144709_intbgw.png"
        alt={`Avatar of ${props.name}`}
      />
      <Text fontWeight="medium">{props.name}</Text>
      <Text>—</Text>
      <Text>{props.date.toLocaleDateString()}</Text>
    </HStack>
  );
}

function PropertyList({ isSignedIn, wallet, contractId }) {

  const { isOpen: listingModalOpen, onOpen: openListingModal, onClose: closeListingModal } = useDisclosure();
  const { isOpen: transferModalOpen, onOpen: openTransferModal, onClose: closeTransferModal } = useDisclosure();
  const [currentModal, setCurrentModal] = React.useState(null);

  const initialRef = React.useRef(null);
  const finalRef = React.useRef(null);

  const openModal = (modal) => {
    setCurrentModal(modal);
    if (modal === 'listing') {
      openListingModal();
    } else if (modal === 'transfer') {
      openTransferModal();
    }
  };

  const closeModal = () => {
    if (currentModal === 'listing') {
      closeListingModal();
    } else if (currentModal === 'transfer') {
      closeTransferModal();
    }
    setCurrentModal(null);
  };

  const mapStyle = {
    height: '300px', // Set the desired height for the map
    width: '100%', // Adjust the width as needed
  };



  const [formData, setFormData] = useState({
    title: '',
    description: '',
    status: '',
    price: 0,
    area: 0,
    name: '',
    username: '',
    email: '',
    phone: '',
    address: '',
    city: '',
    state: '',
    county: '',
    lat: 0,
    long: 0,
  });

  // property_id :i32, 
  // from_account_str : String, 
  // to_account_str: String

  const [formData1, setFormData1] = useState({
    to_account_str: '',

  });


  console.log(wallet.accountId)

  // is_available: bool,
  // title: String,
  // description: String,
  // status: String,
  // price: i32,
  // area: i32,
  // name: String,
  // username: String,
  // email: String,
  // phone: String,
  // address: String,
  // city: String,
  // state: String,
  // county: String,
  // lat: f32,
  // long: f32,


  const [properties, setProperties] = useState([]);
  const [uiPleaseWait, setUiPleaseWait] = useState(true);

  const [mode, setMode] = useState('account');

  useEffect(() => {

    getProperties().then(setProperties);

  }
    , []);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };



  const handleInputChange1 = (e) => {
    const { name, value } = e.target;
    setFormData1({ ...formData1, [name]: value });
  };






  const handleSubmit = async () => {
    // Call the NEAR Protocol function to post the job
    // await postJobToSmartContract(formData);
    let send_p = parseFloat(formData.project_budget);

    let st = send_p.toString();

    console.log(st)

    const deposit = utils.format.parseNearAmount(st);


    console.log("form data is", formData);

    const is_available = true
    const title = formData.title;
    const description = formData.description;
    const status = formData.status
    const price = Number(formData.price);
    const area = Number(formData.area);
    const name = formData.name;
    const username = formData.username;
    const email = formData.email;
    const phone = formData.phone;
    const address = formData.address;
    const city = formData.city;
    const state = formData.state;
    const county = formData.state;
    const lat = parseFloat(formData.lat);
    const long = parseFloat(formData.long);

    console.log("lat", lat);



    // const jsonData = JSON.stringify(updatedFormData);

    wallet
      .callMethod({
        method: "add_property",
        args: {
          is_available: is_available,
          title: title,
          description: description,
          status: status,
          price: price,
          area: area,
          name: name,
          username: username,
          email: email,
          phone: phone,
          address: address,
          city: city,
          state: state,
          county: county,
          lat: lat,
          long: long,
        },
        contractId: contractId
      })
      .then(async () => {
        return getProperties();
      })
      .then(setProperties)
      .finally(() => {
        setUiPleaseWait(false);
      });



    // Update formData with the modified copy
    setFormData(formData);

    closeModal(); // Close the modal after posting the job
  };

  const handleSubmitTransfer = async (id) => {

    const property_id = id;
    const to_account_str = formData1.to_account_str;



    // const jsonData = JSON.stringify(updatedFormData);


    console.log("Transfer to", to_account_str);


    try {
      wallet
        .callMethod({
          method: "transfer_property_using_account",
          args: {
            property_id: property_id,
            to_account: to_account_str,
          },
          contractId: contractId
        })
        .then(async (response) => {
          // Handle the response from the API call
          console.log("Response:", response);

          // Get additional properties
          return getProperties();
        })
        .then((properties) => {
          // Handle properties obtained in the chain
          setProperties(properties);
        })
        .catch((error) => {
          // Handle any errors that occurred in the chain
          console.error("An error occurred:", error);
        })
        .finally(() => {
          // Finally block will execute regardless of success or failure
          setUiPleaseWait(false);
        });

    } catch (error) {
      console.error("An error occurred:", error);
    }



    // Update formData with the modified copy
    setFormData(formData1);

    closeModal(); // Close the modal after posting the job
  };


  function getProperties() {
    console.log(contractId)
    return wallet.viewMethod({ method: "get_property_all", contractId });


  };


  console.log("Properties", properties)

  const handleModeChange = (selectedMode) => {
    setMode(selectedMode); // Update the mode based on user selection
  };


  return (
    <Container maxW={'7xl'} p="12">
      <>
        <Button onClick={() => openModal('listing')}>Add Listing</Button>
        <Modal
          isOpen={listingModalOpen && currentModal === 'listing'}
          onClose={closeModal}
          initialFocusRef={initialRef}
          finalFocusRef={finalRef}
        >
          <ModalOverlay />
          <ModalContent>
            <ModalHeader>Add Listing</ModalHeader>
            <ModalCloseButton />
            <ModalBody pb={6}>
              <FormControl>
                <FormLabel>Title</FormLabel>
                <Input
                  type="text"
                  name="title"
                  placeholder="Title"
                  value={formData.title}
                  onChange={handleInputChange}
                />
              </FormControl>

              <FormControl mt={4}>
                <FormLabel>Description</FormLabel>
                <Textarea
                  name="description"
                  placeholder="property description"
                  value={formData.description}
                  onChange={handleInputChange}
                  size="sm"
                />
              </FormControl>

              <FormControl mt={4}>
                <FormLabel>Status</FormLabel>
                <Input
                  type="text"
                  name="status"
                  placeholder="property status"
                  value={formData.status}
                  onChange={handleInputChange}
                />
              </FormControl>

              <HStack>
                <Box>
                  <FormControl>
                    <FormLabel>Price</FormLabel>
                    <Input
                      type="number"
                      name="price"
                      placeholder="Enter amount"
                      value={formData.price}
                      onChange={handleInputChange}
                    />
                  </FormControl>
                </Box>
                <Box>
                  <FormControl>
                    <FormLabel>Area</FormLabel>
                    <Input
                      type="number"
                      name="area"
                      placeholder="Enter area code"
                      value={formData.area}
                      onChange={handleInputChange}
                    />
                  </FormControl>
                </Box>
              </HStack>

              <HStack>
                <Box>
                  <FormControl mt={4}>
                    <FormLabel>Phone</FormLabel>
                    <Input
                      type="text"
                      name="phone"
                      placeholder="Enter valid phone number"
                      value={formData.phone}
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
                    <FormLabel>Name</FormLabel>
                    <Input
                      type="text"
                      name="name"
                      placeholder="Enter name"
                      value={formData.name}
                      onChange={handleInputChange}
                    />
                  </FormControl>
                </Box>
                <Box>
                  <FormControl mt={4}>
                    <FormLabel>Username</FormLabel>
                    <Input
                      type="text"
                      name="username"
                      placeholder="Enter username"
                      value={formData.username}
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
                <Box>
                  <FormControl mt={4}>
                    <FormLabel>City</FormLabel>
                    <Input
                      type="text"
                      name='city'
                      placeholder="Enter city"
                      value={formData.city}
                      onChange={handleInputChange}
                    />
                  </FormControl>
                </Box>
              </HStack>

              <HStack>
                <Box>
                  <FormControl mt={4}>
                    <FormLabel>State</FormLabel>
                    <Input
                      type="text"
                      name="state"
                      placeholder="Enter state"
                      value={formData.state}
                      onChange={handleInputChange}
                      size="sm"
                    />
                  </FormControl>
                </Box>
                <Box>
                  <FormControl mt={4}>
                    <FormLabel>County</FormLabel>
                    <Input
                      type="text"
                      name="county"
                      placeholder="Enter county"
                      value={formData.county}
                      onChange={handleInputChange}
                      size="sm"
                    />
                  </FormControl>
                </Box>
              </HStack>


              <HStack>
                <Box>

                  <FormControl>
                    <FormLabel>Latitude</FormLabel>
                    <Input
                      type="number"
                      name="lat"
                      placeholder="Enter latitude"
                      value={formData.lat}
                      onChange={handleInputChange}
                      step="any"
                    />
                  </FormControl>
                </Box>
                <Box>
                  <FormControl>
                    <FormLabel>Longitude</FormLabel>
                    <Input
                      type="number"
                      name="long"
                      placeholder="Enter longitude"
                      value={formData.long}
                      onChange={handleInputChange}
                      step="any"
                    />
                  </FormControl>
                </Box>
              </HStack>

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

      <Heading as="h6" padding="0.5rem 0 0">Properties</Heading>
      {properties.length > 0 ? (
        properties.map((property, index) =>
          <>
            <Box
              key={index}
              marginTop={{ base: '1', sm: '5' }}
              display="flex"
              flexDirection={{ base: 'column', sm: 'row' }}
              justifyContent="space-between">
              <Box
                display="flex"
                flex="1"
                marginRight="3"
                position="relative"
                alignItems="center">
                <Box
                  width={{ base: '100%', sm: '85%' }}
                  zIndex="2"
                  marginLeft={{ base: '0', sm: '5%' }}
                  marginTop="5%">
                  <Box textDecoration="none" _hover={{ textDecoration: 'none' }}>
                    {property.owner}
                  </Box>
                </Box>
                <Box zIndex="1" width="100%" position="absolute" height="100%">
                  <Box

                    opacity="0.4"
                    height="100%"
                  />
                </Box>
              </Box>
              <Box
                display="flex"
                flex="1"
                flexDirection="column"
                justifyContent="center"
                marginTop={{ base: '3', sm: '0' }}>
                {/* <PropertyTags tags={} /> */}
                <Heading marginTop="2" fontSize={15} textAlign={'left'}>
                  <Text textDecoration="none" _hover={{ textDecoration: 'none' }}>
                    {property.title}
                    {property.is_available ? (
                      <div></div>
                    ) : (
                      // Render the "Removed" badge when the job is not available
                      <span style={{ paddingLeft: '3', marginLeft: '3' }}>
                        <Badge colorScheme='red'>Not Available</Badge>
                      </span>
                    )}
                  </Text>
                </Heading>
                <Text
                  as="p"
                  marginTop="2"
                  color={useColorModeValue('gray.700', 'gray.200')}
                  fontSize="lg">
                  {property.description}
                </Text>
                <Text textDecoration="none" color={'green'} _hover={{ textDecoration: 'none' }}>
                  {property.status}
                </Text>
                <Text textDecoration="none" marginTop={5} marginBottom={5} _hover={{ textDecoration: 'none' }}>
                  Price: {property.price} <span style={{ color: 'Highlight' }}> </span>
                </Text>
                {/* <Text textDecoration="none" marginTop={1} marginBottom={1} _hover={{ textDecoration: 'none' }}>
                  lat: {property.lat} <span style={{ color: 'Highlight' }}> </span>
                </Text>
                <Text textDecoration="none" marginTop={1} marginBottom={1} _hover={{ textDecoration: 'none' }}>
                  long: {property.long} <span style={{ color: 'Highlight' }}> </span>
                </Text> */}
                {/* <PropertyOwner name={} date={new Date('2021-04-06T19:01:27Z')} /> */}
                <HStack>
                  <Box>
                    <Popover>
                      <PopoverTrigger>
                        <Button>Contacts</Button>
                      </PopoverTrigger>
                      <PopoverContent>
                        <PopoverArrow />
                        <PopoverCloseButton />
                        <PopoverHeader>Contact Information</PopoverHeader>
                        <PopoverBody>
                          <Text textDecoration="none" marginTop={1} marginBottom={2} _hover={{ textDecoration: 'none' }} color={'blue'}>
                            {property.contact_information.name}
                          </Text>
                          <Text textDecoration="none" marginTop={1} marginBottom={1} _hover={{ textDecoration: 'none' }} color={'blue'}>
                            {property.contact_information.phone}
                          </Text>
                          <Text textDecoration="none" marginTop={1} marginBottom={1} _hover={{ textDecoration: 'none' }} color={'blue'}>
                            {property.contact_information.email}
                          </Text>
                          <Text textDecoration="none" marginTop={1} marginBottom={1} _hover={{ textDecoration: 'none' }} color={'blue'}>
                            {property.contact_information.username}
                          </Text>
                        </PopoverBody>
                      </PopoverContent>
                    </Popover>
                  </Box>
                  <Box>
                    <Popover>
                      <PopoverTrigger>
                        <Button>Location</Button>
                      </PopoverTrigger>
                      <PopoverContent>
                        <PopoverArrow />
                        <PopoverCloseButton />
                        <PopoverHeader>Location Info</PopoverHeader>
                        <PopoverBody>
                          <Text textDecoration="none" marginTop={1} marginBottom={2} _hover={{ textDecoration: 'none' }} color={'green'}>
                            {property.location.address}
                          </Text>
                          <Text textDecoration="none" marginTop={1} marginBottom={2} _hover={{ textDecoration: 'none' }} color={'green'}>
                            {property.location.city}
                          </Text>
                          <Text textDecoration="none" marginTop={1} marginBottom={2} _hover={{ textDecoration: 'none' }} color={'green'}>
                            {property.location.county}
                          </Text>
                          <Text textDecoration="none" marginTop={1} marginBottom={2} _hover={{ textDecoration: 'none' }} color={'green'}>
                            {property.location.state}
                          </Text>
                          <Text textDecoration="none" marginTop={1} marginBottom={2} _hover={{ textDecoration: 'none' }} color={'green'}>
                            lat: {property.location.lat}  long: {property.location.long}
                          </Text>
                        </PopoverBody>
                      </PopoverContent>
                    </Popover>

                  </Box>
                </HStack>
                {property.is_available ? (
                  <>
                    <Button onClick={() => openModal('transfer')} background={'green'} color={'white'} marginTop={3}>Transfer</Button>
                    <Modal
                      isOpen={transferModalOpen && currentModal === 'transfer'}
                      onClose={closeModal}
                      initialFocusRef={initialRef}
                      finalFocusRef={finalRef}
                    >
                      <ModalOverlay />
                      <ModalContent>
                        <ModalHeader>Transfer</ModalHeader>
                        <ModalCloseButton />
                        <ModalBody pb={6}>

                          {/* Mode switch */}
                          <Button colorScheme={mode === 'account' ? 'blue' : 'gray'}>
                            Transfer by Account
                          </Button>

                          <>
                            <FormControl>
                              <FormLabel>To Account</FormLabel>
                              <Input
                                type="text"
                                name="to_account_str"
                                placeholder="To Account ID"
                                value={formData1.to_account_str}
                                onChange={handleInputChange1}
                              />
                            </FormControl>
                          </>

                        </ModalBody>
                        <ModalFooter>
                          <Button colorScheme="blue" mr={3} onClick={() => handleSubmitTransfer(property.id)}>
                            Post
                          </Button>
                          <Button onClick={closeModal}>Cancel</Button>
                        </ModalFooter>
                      </ModalContent>
                    </Modal>
                  </>
                ) : (
                  // Render the "Removed" badge when the job is not available
                  <span style={{ paddingLeft: '0' }}>

                  </span>
                )}
              </Box>

            </Box>
            <Divider />
          </>

        )
      ) : (
        // If the jobs array is empty, display a message
        <p>No properties available at the moment.</p>
      )}
      <Divider />
    </Container>
  );
}

export default PropertyList;
