# Import necessary libraries
from starkware.crypto.signature.signature import validate_signature

# Define the contract state for land ownership.
contract LandOwnership:
    owner: public(uint256)
    coordinates: public(uint256[2])

    # Initialize the contract with the owner's address and land coordinates.
    @public
    @init
    def __init__(owner_address: uint256, x_coord: uint256, y_coord: uint256):
        self.owner = owner_address
        self.coordinates = [x_coord, y_coord]

    # Transfer ownership to a new address.
    @public
    @payable
    def transfer_ownership(new_owner: uint256, signature: uint256[2]):
        # Verify the BLS signature to ensure the authenticity of the transfer request.
        is_valid_signature = verify_bls(self.coordinates, signature, new_owner)

        # Ensure the new owner is different from the current owner and the signature is valid.
        require(new_owner != self.owner, "New owner must be different.")
        require(is_valid_signature, "Invalid signature.")

        # Update the owner.
        self.owner = new_owner

    # Function to verify the BLS signature.
    @private
    def verify_bls(coordinates: uint256[2], signature: uint256[2], owner: uint256) -> bool:
        # Convert coordinates to bytes for the signature verification.
        message = concat(coordinates)
        
        # Validate the BLS signature.
        return validate_signature(message, signature, owner)
