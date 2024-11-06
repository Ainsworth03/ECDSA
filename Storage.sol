//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract storeSignature{

    struct signatureData {
        bytes signature;
        uint256 timestamp;
    }

    mapping (bytes32 => signatureData) private signatures;

    function addSignature(bytes32 _hash, bytes memory _signature) public{
        require(signatures[_hash].timestamp != 0, 'Certificate already signed!');
        signatures[_hash] = signatureData(_signature, block.timestamp);
    }

    function retrieveSignature(bytes32 _hash) public view returns(bytes memory, uint256){
        signatureData memory sigData = signatures[_hash];
        require(sigData.timestamp != 0, 'Certificate is not signed!');
        return(sigData.signature, sigData.timestamp);
    }
}
