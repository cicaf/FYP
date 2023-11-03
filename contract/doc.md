## Interacting with the smart contract

The smart contract exposes the following methods(with the parameters)

1. add_user<br/>
   `(first_name: String, last_name: String, about_yourself: String, phone_number: String, address: String, email: String, password: String)`
2. transfer_property_using_account<br/>
   `(property_id :i32, from_account_str : String, to_account_str: String)`
3. transfer_property_using_account<br/>
   `(property_id :i32, from_account_str : String, to_account_str: String)`
4. transfer_property_using_account<br/>
   `( property_id :i32, from_email : String, to_email: String)`
5. get_users<br/>
   `no params`
6. get_property_all <br/>
   `no params`
7. login_password <br/>
   `email: String, password: String`
8. get_property_available <br/>
9. add_property
   `(is_available: bool,   title: String,   description: String, 
   status: String,   price: i32,   area: i32,   name: String,
   username: String,   email: String,
   phone: String,   address: String,
   city: String,   state: String,   county: String,
   lat: f32,   long: f32)`