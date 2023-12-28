import React from 'react';
import { Box, SimpleGrid, Icon, Text, Stack, Flex } from '@chakra-ui/react';
import { FcAssistant, FcDonate, FcInTransit } from 'react-icons/fc';

function Feature({ title, text, icon }) {
  return (
    <Stack>
      <Flex
        w={16}
        h={16}
        align={'center'}
        justify={'center'}
        color={'white'}
        rounded={'full'}
        bg={'gray.100'}
        mb={1}
      >
        {icon}
      </Flex>
      <Text fontWeight={600}>{title}</Text>
      <Text color={'gray.600'}>{text}</Text>
    </Stack>
  );
}

export default function CryptoFreelancerWebsite() {
  return (
    <Box p={4}>
      <SimpleGrid columns={{ base: 1, md: 3 }} spacing={10}>
        <Feature
          icon={<Icon as={FcAssistant} w={10} h={10} />}
          title={'Expert Land Consultants'}
          text={
            'Connect with experienced land consultants who can guide you through land purchase, legalities, and investment opportunities.'
          }
        />
        <Feature
          icon={<Icon as={FcDonate} w={10} h={10} />}
          title={'Secure Land Transactions'}
          text={
            'We offer secure payment options for land transactions, ensuring safe and transparent dealings between buyers and sellers.'
          }
        />
        <Feature
          icon={<Icon as={FcInTransit} w={10} h={10} />}
          title={'Efficient Land Purchase'}
          text={
            'Experience a streamlined process for buying land, ensuring swift and reliable transactions on our platform.'
          }
        />
      </SimpleGrid>
    </Box>
  );
}
