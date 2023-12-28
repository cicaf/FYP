use near_sdk::{near_bindgen, AccountId, env};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::Vector;
use near_sdk::serde::{Deserialize, Serialize};

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub enum PropertyType {
    House,
    Commercial,
    Apartment,
    Lot,
    Garage,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub enum PropertyStatus {
    Sale,
    Rent,
    NotAvailable,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct PropertyContactInformation {
    pub user_id: i32,
    pub name: String,
    pub username: String,
    pub email: String,
    pub phone: String,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct PropertyLocation {
    pub address: String,
    pub city: String,
    pub state: String,
    pub county: String,
    pub lat: f32,
    pub long: f32,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct PropertyMedia {
    pub id: i32,
    pub url: String,
}



#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct Property {
    pub id: i32,
    pub owner: AccountId,
    pub is_available: bool,
    pub title: String,
    pub description: String,
    pub status: PropertyStatus,
    pub price: i32,
    pub area: i32,
    pub contact_information: PropertyContactInformation,
    pub location: PropertyLocation,

}

impl Default for Property {
    fn default() -> Self {
        Self {
            id: 0,
            owner: env::current_account_id(),
            is_available: false,
            title: "".to_string(),
            description: "".to_string(),
            status: PropertyStatus::NotAvailable,
            price: 0,
            area: 0,

            contact_information: PropertyContactInformation {
                name: "".to_string(),
                email: "".to_string(),
                phone: "".to_string(),
                user_id: 0,
                username: "".to_string(),
            },
            location: PropertyLocation {
                address: "".to_string(),
                city: "".to_string(),
                lat: 0.0,
                long: 0.0,
                county: "".to_string(),
                state: "".to_string(),
            },
        }
    }
}