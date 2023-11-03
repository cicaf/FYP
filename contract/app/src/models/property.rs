use near_sdk::store::Vector;
use near_sdk::{near_bindgen, env, AccountId};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub enum PropertyType {
    House,
    Commercial,
    Apartment,
    Lot,
    Garage,

}
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub enum PropertyStatus {
    Sale,
    Rent,
    NotAvailable,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct PropertyContactInformation {
    pub user_id:i32,
    pub  name: String,
    pub  username: String,
    pub  email: String,
    pub  phone: String,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct PropertyLocation {
    pub address: String,
    pub city: String,
    pub state: String,
    pub county: String,
    pub lat: f32,
    pub long: f32,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct PropertyMedia {
    pub  id: i32,
    pub url: String,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct PropertyRating {
    pub rating:f32,
    pub  user_id:i32
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct Property {
    pub id: i32,
    pub owner:AccountId,
    pub is_available:bool,
    pub title: String,
    pub description: String,
    pub status: PropertyStatus,
    pub price: i32,
    pub area: i32,
    pub contact_information : PropertyContactInformation,
    pub location: PropertyLocation,
    pub rating: Vector<PropertyRating>
}