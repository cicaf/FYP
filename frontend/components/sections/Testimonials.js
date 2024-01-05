import React from 'react';
import {
  Box,
  Flex,
  Heading,
  Text,
  Stack,
  Container,
  Avatar,
  useColorModeValue,
} from '@chakra-ui/react';

const Testimonial = (props) => {
  const { children } = props;

  return <Box>{children}</Box>;
};

const TestimonialContent = (props) => {
  const { children } = props;

  return (
    <Stack
      bg={useColorModeValue('white', 'gray.800')}
      boxShadow={'lg'}
      p={8}
      rounded={'xl'}
      align={'center'}
      pos={'relative'}
      _after={{
        content: `""`,
        w: 0,
        h: 0,
        borderLeft: 'solid transparent',
        borderLeftWidth: 16,
        borderRight: 'solid transparent',
        borderRightWidth: 16,
        borderTop: 'solid',
        borderTopWidth: 16,
        borderTopColor: useColorModeValue('white', 'gray.800'),
        pos: 'absolute',
        bottom: '-16px',
        left: '50%',
        transform: 'translateX(-50%)',
      }}
    >
      {children}
    </Stack>
  );
};

const TestimonialHeading = (props) => {
  const { children } = props;

  return (
    <Heading as={'h3'} fontSize={'xl'}>
      {children}
    </Heading>
  );
};

const TestimonialText = (props) => {
  const { children } = props;

  return (
    <Text
      textAlign={'center'}
      color={useColorModeValue('gray.600', 'gray.400')}
      fontSize={'sm'}
    >
      {children}
    </Text>
  );
};

const TestimonialAvatar = ({
  src,
  name,
  title,
}) => {
  return (
    <Flex align={'center'} mt={8} direction={'column'}>
      <Avatar src={src} mb={2} />
      <Stack spacing={-1} align={'center'}>
        <Text fontWeight={600}>{name}</Text>
        <Text fontSize={'sm'} color={useColorModeValue('gray.600', 'gray.400')}>
          {title}
        </Text>
      </Stack>
    </Flex>
  );
};

export default function CryptoFreelancerTestimonials() {
  return (
    <Box bg={'gray.100'}>
    <Container maxW={'7xl'} py={16} as={Stack} spacing={12}>
      <Stack spacing={0} align={'center'}>
        <Heading>PROPERTY SERVICES</Heading>
        <Text>What our clients are saying about our property services.</Text>
      </Stack>
      <Stack
        direction={{ base: 'column', md: 'row' }}
        spacing={{ base: 10, md: 4, lg: 10 }}
      >
        <Testimonial>
          <TestimonialContent>
            <TestimonialHeading>Outstanding Land Stewards</TestimonialHeading>
            <TestimonialText>
              "The platform connected me with exceptional land stewards who provided unparalleled care and management for my property. Their dedication was truly impressive."
            </TestimonialText>
          </TestimonialContent>
          <TestimonialAvatar
            src={'URL_to_your_image'}
            name={'John Doe'}
            title={'Property Owner'}
          />
        </Testimonial>
        <Testimonial>
          <TestimonialContent>
            <TestimonialHeading>Streamlined Land Transactions</TestimonialHeading>
            <TestimonialText>
              "I experienced seamless and secure land transactions through this platform. Their efficient process ensured peace of mind throughout the acquisition."
            </TestimonialText>
          </TestimonialContent>
          <TestimonialAvatar
            src={'URL_to_your_image'}
            name={'Alice Smith'}
            title={'Real Estate Investor'}
          />
        </Testimonial>
        <Testimonial>
          <TestimonialContent>
            <TestimonialHeading>Seasoned Land Advisors</TestimonialHeading>
            <TestimonialText>
              "The experienced land advisors I found here guided me through insightful decisions, offering invaluable expertise and perspective."
            </TestimonialText>
          </TestimonialContent>
          <TestimonialAvatar
            src={'URL_to_your_image'}
            name={'Emma Johnson'}
            title={'Property Consultant'}
          />
        </Testimonial>
      </Stack>
    </Container>
  </Box>
  );
}
