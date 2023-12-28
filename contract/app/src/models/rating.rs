use near_sdk::{near_bindgen, AccountId, env};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct PropertyRating {
    pub rating: f32,
    pub user_id: i32,
    pub property_id: i32,
}

