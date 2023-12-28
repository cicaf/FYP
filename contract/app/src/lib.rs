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
use std::collections::HashMap; 


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
    properties: HashMap<u128, Property>,
    users: HashMap<AccountId, User>,
    ratings: HashMap<u128, PropertyRating>,
    user_id:u128,
    rating_id:u128,
    property_id:u128,
}

// Define the default, which automatically initializes the contract
impl Default for PropertySystem {
    fn default() -> Self {
        Self {
            greeting: DEFAULT_GREETING.to_string(),
            properties: HashMap::new(),
            users: HashMap::new(),
            ratings:HashMap::new(),
            user_id:0,
            rating_id:0,
            property_id:0,
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



    pub fn add_user(
        &mut self,
        first_name: String, 
        last_name: String, 
        about_yourself: String, 
        phone_number: String, 
        address: String, 
        email: String, 
        password: String
    ) {

        let new_user_id = self.user_id + 1;

        let account_id = env::predecessor_account_id();

        self.user_id += 1;

        let user = User {
            id: new_user_id as i32,
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
        self.users.insert(account_id,user);
    }

    pub fn transfer_property_using_account(
        &mut self,
        property_id :u128, 
        to_account: AccountId
    ) ->  String {


        let from_account = env::predecessor_account_id();
        // Check if account_id_to_check is in users HashMap
        if let Some(property) = self.properties.get_mut(&property_id) {
            if property.owner == from_account {
                property.owner = to_account;
                property.is_available = false;
                "Property transferred successfully.".to_string()
            } else {
                "Only the owner can transfer ownership.".to_string()
            }
        } else {
            "Property ID does not exist.".to_string()
        }

     
    }



    // Public method - returns all the users
    pub fn get_users(self) -> Vec<User> {

        let mut result = self.users.values().cloned().collect::<Vec<User>>();
   
        result
    }

    // Public method - returns all the property
    pub fn get_property_all(&self) -> Vec<Property> {

        let mut result = self.properties.values().cloned().collect::<Vec<Property>>();
            
        // Sort the vector by job_id
        result.sort_by(|a, b| a.id.cmp(&b.id));
        
        result
    }

    // pub fn login_password(&self, email: String, password: String) -> (Option<&User>, String) {
    //     let user = self.users.iter().find(|item| item.email == email);

    //     return match user {
    //         Some(data) => {
    //             if data.password == password {
    //                 (Option::Some(data), OKAY.to_string())
    //             } else {
    //                 (Option::None, ACCOUNT_WRONG_PASSWORD.to_string())
    //             }
    //         }
    //         None => (Option::None, "email not found in system".to_string())
    //     };
    // }

    
    pub fn get_property_available(&self) -> Vec<&Property> {
        self.properties
            .values()
            .filter(|property| property.is_available)
            .collect()
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

        let the_owner = env::signer_account_id();
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

        let new_property_id = self.property_id + 1;

        self.property_id += 1;

        let property_item = Property {
            owner: the_owner,
            id: new_property_id.clone() as i32,
            is_available,
            title,
            description,
            status: status_item,
            price,
            area,
            contact_information,
            location,

        };
        self.properties.insert(new_property_id,property_item);
        return "okay".to_string();
    }

    pub fn get_properties_for_account(&self, account_id: AccountId) -> Vec<&Property> {
        self.properties
            .values()
            .filter(|property| property.owner == account_id)
            .collect()
    }

    pub fn get_property(&self, property_id: u128) -> Option<Property> {
        self.properties.get(&property_id).cloned()
    }

    pub fn get_user(&self, account_id: AccountId) -> Option<User> {
        self.users.get(&account_id).cloned()
    }
}

/*
 * The rest of this file holds the inline tests for the code above
 * Learn more about Rust tests: https://doc.rust-lang.org/book/ch11-01-writing-tests.html
 */
#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts};


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

        let property = contract.get_property(1);

        let new_property = property.unwrap();

        assert_eq!(new_property.title,"My jumbo system".to_string());
        assert_eq!(new_property.price,1_000_000);

        let the_owner = env::signer_account_id();

        assert_eq!(new_property.owner, the_owner.clone());

        let property_for_account = contract.get_properties_for_account(the_owner);

        assert_eq!(property_for_account[0].area, 5000);
        
        

    }

    #[test]
    fn add__user() {
        let mut contract = PropertySystem::default();

        let the_user = env::signer_account_id();

        contract.add_user(
            "howdy".to_string(),
            "howdy".to_string(),
            "howdy".to_string(),
            "howdy".to_string(),
            "howdy".to_string(),
            "howdy@mail.com".to_string(),
            "howdy".to_string(),
        );

        let user = contract.get_user(the_user).unwrap();

        assert_eq!(user.first_name,"howdy".to_string());
        assert_eq!(user.email,"howdy@mail.com".to_string());
    }

    #[test]
    fn add_get_property_then_transfer() {

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

        let property = contract.get_property(1);

        let new_property = property.unwrap();

        assert_eq!(new_property.title,"My jumbo system".to_string());
        assert_eq!(new_property.price,1_000_000);

        let the_owner = env::signer_account_id();

        assert_eq!(new_property.owner, the_owner.clone());

        let property_for_account = contract.get_properties_for_account(the_owner);

        assert_eq!(property_for_account[0].area, 5000);

        contract.transfer_property_using_account(1,accounts(1));

        let property_1 = contract.get_property(1).unwrap();

        assert_eq!(property_1.owner, accounts(1));

        let property_for_account_1 = contract.get_properties_for_account(accounts(1));

        assert_eq!(property_for_account_1[0].area, 5000);
        


        
        

    }
}
