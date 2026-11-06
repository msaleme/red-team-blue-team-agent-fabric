// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

/// X4-069's client-controlled token: the token a client names in `accepted.asset`.
///
/// Testnet only (Base Sepolia). A plain EIP-3009 token with nothing else in it: no owner,
/// no hooks, no callbacks, no external calls, no upgrade path. The whole supply is minted
/// once, to `holder`, in the constructor. It is worth nothing, which is the point of the
/// probe: a payment in it reads correctly in the logs (right amount, right payTo) and pays
/// the server nothing.
///
/// It implements exactly what the stock x402 eip3009 facilitator reads and calls
/// (x402 Python 2.26.0, mechanisms/evm/exact/eip3009_utils.py): name(), version(),
/// balanceOf(), authorizationState(), and transferWithAuthorization() with a v/r/s
/// signature (the form the facilitator uses for a 65-byte signature).
contract ClientTestToken {
    string public name;
    string public constant version = "1";
    string public constant symbol = "CTT";
    uint8 public constant decimals = 6;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(bytes32 => bool)) public authorizationState;

    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    event Transfer(address indexed from, address indexed to, uint256 value);
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    constructor(string memory name_, address holder, uint256 supply) {
        name = name_;
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name_)), keccak256(bytes(version)), block.chainid, address(this)));
        totalSupply = supply;
        balanceOf[holder] = supply;
        emit Transfer(address(0), holder, supply);
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _move(msg.sender, to, value);
        return true;
    }

    function transferWithAuthorization(
        address from, address to, uint256 value, uint256 validAfter, uint256 validBefore,
        bytes32 nonce, uint8 v, bytes32 r, bytes32 s
    ) external {
        require(block.timestamp > validAfter, "authorization is not yet valid");
        require(block.timestamp < validBefore, "authorization is expired");
        require(!authorizationState[from][nonce], "authorization is used");
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, keccak256(abi.encode(
            TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce))));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0) && signer == from, "invalid signature");
        authorizationState[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);
        _move(from, to, value);
    }

    function _move(address from, address to, uint256 value) private {
        require(to != address(0), "transfer to the zero address");
        require(balanceOf[from] >= value, "transfer amount exceeds balance");
        unchecked { balanceOf[from] -= value; }
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }
}
