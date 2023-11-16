mod models;

// Find all our documentation at https://docs.near.org
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{AccountId, env, log, near_bindgen};
use near_sdk::store::Vector;
use models::user::User;
use std::string::String;
use models::rating::PropertyRating;
use models::property::{Property, PropertyLocation};
use crate::models::property::{PropertyContactInformation, PropertyStatus};

const DEFAULT_GREETING: &str = "Hello";
const OKAY: &str = "okay";
const ACCOUNT_BLOCKED: &str = "account blocked";
const ACCOUNT_NOT_FOUND: &str = "account not found";
const EMAIL_NOT_FOUND: &str = "email not found in system";
const ACCOUNT_WRONG_PASSWORD: &str = "account wrong password";
const ACCOUNT_NOT_OWNER: &str = "account does not own property";
const ACCOUNT_TARGET_DOES_NOT_EXIST: &str = "account target does not exist";
const ACCOUNT_FROM_DOES_NOT_EXIST: &str = "from account does not exist";
const PROPERTY_DOES_NOT_EXIST: &str = "from account does not exist";

// Define the contract structure
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
struct PropertySystem {
    greeting: String,
    property: Vector<Property>,
    users: Vector<User>,
    ratings: Vector<PropertyRating>,
}

// Define the default, which automatically initializes the contract
impl Default for PropertySystem {
    fn default() -> Self {
        Self {
            greeting: DEFAULT_GREETING.to_string(),
            property: Vector::new(b"r".to_vec()),
            users: Vector::new(b"r".to_vec()),
            ratings:Vector::new(b"r".to_vec()),
        }
    }
}


// Implement the contract structure
#[near_bindgen]
impl PropertySystem {
    // Public: Returns the stored greeting, defaulting to 'Hello'
    pub fn get_greeting(&self) -> String {
        return self.greeting.clone();
    }

    // Public: Takes a greeting, such as 'howdy', and records it
    pub fn set_greeting(&mut self, greeting: String) {
        // Record a log permanently to the blockchain!
        log!("Saving greeting {}", greeting);
        self.greeting = greeting;
    }

    /// Init attribute used for instantiation.
    #[init]
    pub fn new() -> Self {
        // Useful snippet to copy/paste, making sure state isn't already initialized
        assert!(env::state_read::<Self>().is_none(), "Already initialized");
        // Note this is an implicit "return" here
        Self {
            greeting: DEFAULT_GREETING.to_string(),
            property: Vector::new(b"r".to_vec()),
            users: Vector::new(b"r".to_vec()),
            ratings: Vector::new(b"r".to_vec()),
        }
    }


    pub fn add_user(&mut self, first_name: String, last_name: String, about_yourself: String, phone_number: String, address: String, email: String, password: String) {
        let user = User {
            id: (self.users.len() + 1) as i32,
            account: env::signer_account_id(),
            email,
            first_name,
            last_name,
            address,
            phone_number,
            about_yourself,
            password, //todo encrypt
            is_admin: false,
            is_blocked: false,

        };
        self.users.push(user);
    }

    pub fn transfer_property_using_account(&mut self, property_id :i32, from_account_str : String, to_account_str: String) ->  String {

        let from_account = AccountId::new_unchecked(from_account_str);
        let to_account = AccountId::new_unchecked(to_account_str);


        let mut from_user :Option<&User> = Option::None;
        let mut to_user :Option<&User> = Option::None;

        for a_user in self.users.iter() {
            if a_user.account ==from_account {
                from_user=Some(a_user)
            }
            if a_user.account ==to_account{
                to_user=Some(a_user)
            }
        }


        match from_user {
            None => {
                env::log_str("from user does not exist ");
                return ACCOUNT_FROM_DOES_NOT_EXIST.to_string()
            },
            Some(_)=>{
                env::log_str("from user valid")
            }
        }
        match to_user {
            None => {
                env::log_str("to user does not exist ");
                return ACCOUNT_TARGET_DOES_NOT_EXIST.to_string()
            },
            Some(_)=>{
                env::log_str("to user valid")
            }
        }


        // check property exists
        let property_for_transfer =  self.property.iter_mut().find(|item| item.id ==property_id);


        match property_for_transfer {
            None => {
                env::log_str("property does not exist ");
                return PROPERTY_DOES_NOT_EXIST.to_string()
            },
            Some(_)=>{
                env::log_str("property valid")
            }
        }

        for property_item in self.property.iter_mut() {
            if property_item.id == property_id {
                property_item.owner = to_user.unwrap().account.clone();
                property_item.is_available = false;
            }
        }

        OKAY.to_string()
    }



    // Public method - returns all the users
    pub fn get_users(self) -> Vec<User> {
        let mut  users:Vec<User> = vec![];
        for item in self.users.iter() {
            users.push(item.clone());
        }
        return users;
    }

    // Public method - returns all the property
    pub fn get_property_all(&self) -> Vec<Property> {

        let mut  properties:Vec<Property> = vec![];
        for item in self.property.iter() {
            properties.push(item.clone());
        }
        return properties;
    }

    pub fn login_password(&self, email: String, password: String) -> (Option<&User>, String) {
        let user = self.users.iter().find(|item| item.email == email);

        return match user {
            Some(data) => {
                if data.password == password {
                    (Option::Some(data), OKAY.to_string())
                } else {
                    (Option::None, ACCOUNT_WRONG_PASSWORD.to_string())
                }
            }
            None => (Option::None, "email not found in system".to_string())
        };
    }

    pub fn get_property_available(&self) -> Vec<&Property> {
        let mut data: Vec<&Property> = vec![];
        for elem in &mut self.property.iter() {
            data.push(elem);
        }
        data
    }
    pub fn add_property(&mut self,
                        is_available: bool,
                        title: String,
                        description: String,
                        status: String,
                        price: i32,
                        area: i32,
                        name: String,
                        username: String,
                        email: String,
                        phone: String,
                        address: String,
                        city: String,
                        state: String,
                        county: String,
                        lat: f32,
                        long: f32,
    ) -> String {
        let sale = String::from("sale");
        let rent = String::from("rent");
        let not_available = String::from("not_available");
        let status_item = match status {
            sale => PropertyStatus::Sale,
            rent => PropertyStatus::Rent,
            not_available => PropertyStatus::NotAvailable,
            _ => PropertyStatus::NotAvailable
        };
        let contact_information = PropertyContactInformation {
            name,
            username,
            email,
            phone,
            user_id:0
        };
        let location = PropertyLocation {
            address,
            city,
            state,
            county,
            lat,
            long,
        };
        let property_item = Property {
            owner: env::current_account_id(),
            id: (self.property.len() + 1) as i32,
            is_available,
            title,
            description,
            status: status_item,
            price,
            area,
            contact_information,
            location,

        };
        self.property.push(property_item);
        return "okay".to_string();
    }
}

/*
 * The rest of this file holds the inline tests for the code above
 * Learn more about Rust tests: https://doc.rust-lang.org/book/ch11-01-writing-tests.html
 */
#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn add_then_get_property() {
        let mut contract = PropertySystem::default();
        contract.add_property(
            true, // is_available: bool,
            "My jumbo system".to_string(),// title: String,
            "5 bedroom mansion in Ruiru bypass".to_string(), // description: String,
            "sale".to_string(),// status: String,
            1_000_000,// price: i32,
            5000,// area: i32,
            "kenn".to_string(), // name: String,
            "kenn".to_string(),// username: String,
            "sample@email.com".to_string(),// email: String,
            "254717008240".to_string(),// phone: String,
            "254-466 Ruaraka".to_string(),// address: String,
            "Ruiru".to_string(), // city: String,
            "Kiambu".to_string(),// state: String,
            "Kiambu".to_string(),// county: String,
            0.02922,// lat: f32,
            0.1223, // long: f32,
        );
        assert_eq!(
            contract.get_property_all().len(),
            1
        );
        assert_eq!(
            contract.get_property_available().len(),
            1
        );
    }

    #[test]
    fn add_then_get_users_login() {
        let mut contract = PropertySystem::default();
        contract.add_user(
            "howdy".to_string(),
            "howdy".to_string(),
            "howdy".to_string(),
            "howdy".to_string(),
            "howdy".to_string(),
            "howdy@mail.com".to_string(),
            "howdy".to_string(),
        );
        // assert_eq!(
        //     contract.get_users(),
        //     1
        // );
        //login
        // valid password
        // let (res, reason) = contract.login_password("howdy@mail.com".to_string(), "howdy".to_string());
        // assert_eq!(
        //     res,
        //     Some
        // );
        // assert_eq!(
        //     reason,
        //     OKAY.to_string()
        // );

        // email not valid
        let (res2, reason2) = contract.login_password("kkakkakka".to_string(), "".to_string());
        assert_eq!(
            res2,
            None
        );
        assert_eq!(
            reason2,
            EMAIL_NOT_FOUND.to_string()
        );

        // invalid password
        let (res3, reason3) = contract.login_password("howdy@mail.com".to_string(), "".to_string());
        assert_eq!(
            res3,
            None
        );
        assert_eq!(
            reason3,
            ACCOUNT_WRONG_PASSWORD.to_string()
        );
    }
}
