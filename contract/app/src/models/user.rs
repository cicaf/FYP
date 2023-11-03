use near_sdk::{near_bindgen,  AccountId};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct User {
    pub   id: i32,
    pub account:AccountId,
    pub  email: String,
    pub  first_name: String,
    pub  last_name: String,
    pub  address: String,
    pub  phone_number: String,
    pub   about_yourself: String,
    pub password:String,
    pub is_admin:bool,
    pub  is_blocked:bool,
}

