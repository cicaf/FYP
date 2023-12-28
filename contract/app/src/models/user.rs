use near_sdk::{near_bindgen, AccountId, env};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct User {
    pub id: i32,
    pub account: AccountId,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub address: String,
    pub phone_number: String,
    pub about_yourself: String,
    pub password: String,
    pub is_admin: bool,
    pub is_blocked: bool,
}

impl Default for User {
    fn default() -> Self {
        Self {
            id: 0,
            account: env::current_account_id(),
            email: "".to_string(),
            first_name: "".to_string(),
            last_name: "".to_string(),
            address: "".to_string(),
            phone_number: "".to_string(),
            about_yourself: "".to_string(),
            password: "".to_string(),
            is_admin: false,
            is_blocked: false,
        }
    }
}

