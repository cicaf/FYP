## Interacting with the smart contract

The smart contract exposes the following methods(with the parameters)

1. add_user<br/>
   `(first_name: String, last_name: String, about_yourself: String, phone_number: String, address: String, email: String, password: String)`
2. transfer_property_using_account<br/>
   `(property_id :i32, from_account_str : String, to_account_str: String)`
3. transfer_property_using_account<br/>
   `(property_id :i32, from_account_str : String, to_account_str: String)`
4. transfer_property_using_email<br/>
   `( property_id :i32, from_email : String, to_email: String)`
5. get_users<br/>
   `no params`
6. get_property_all <br/>
   `no params`
7. login_password <br/>
   `email: String, password: String`
8. get_property_available <br/>
   `no params`
9. add_property
   `(is_available: bool,   title: String,   description: String, 
   status: String,   price: i32,   area: i32,   name: String,
   username: String,   email: String,
   phone: String,   address: String,
   city: String,   state: String,   county: String,
   lat: f32,   long: f32)`


## Deploy 
1. `cd contract/app && ./build`
2. `near create-account land_systems.mzalendo254.testnet --masterAccount mzalendo254.testnet`
   ```Saving key to '/home/kamau/.near-credentials/testnet/land_systems.mzalendo254.testnet.json'
   Account land_systems.mzalendo254.testnet for network "testnet" was created.```

3. `near dev-deploy --wasmFile ./target/wasm32-unknown-unknown/release/land_system.wasm --accountId land_systems.mzalendo254.testnet `
   ```Starting deployment. Account id: dev-1699006645642-96863308071582, node: https://rpc.testnet.near.org, helper: https://helper.testnet.near.org, file: ./target/wasm32-unknown-unknown/release/land_system.wasm
   Transaction Id 9Q3k4Ck88GUoVfqub3huhoGgpcuQRxWC8SE3sh7jfFUC
   To see the transaction in the transaction explorer, please open this url in your browser
   https://explorer.testnet.near.org/transactions/9Q3k4Ck88GUoVfqub3huhoGgpcuQRxWC8SE3sh7jfFUC
   Done deploying to dev-1699006645642-96863308071582
   ```
4. `near view   dev-1699006645642-96863308071582  get_greeting '{}' --accountId land_systems.mzalendo254.testnet`
5. `near call   dev-1699006645642-96863308071582  set_greeting '{greeting:"mursik...."}'`