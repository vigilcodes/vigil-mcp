// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title VIGIL Token
/// @notice ERC-20 token for the VIGIL onchain security scanner protocol
/// @dev Deployed on Base mainnet. Used for staking, governance, and fee distribution.
contract VigilToken is ERC20, ERC20Burnable, ERC20Permit, AccessControl, ReentrancyGuard {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    uint256 public constant MAX_SUPPLY = 100_000_000 * 1e18; // 100M tokens
    uint256 public constant INITIAL_SUPPLY = 40_000_000 * 1e18; // 40% at TGE

    // Vesting tracking
    mapping(address => uint256) public vestedAmount;
    mapping(address => uint256) public vestingStart;
    mapping(address => uint256) public vestingDuration;
    mapping(address => uint256) public claimedAmount;

    event Vested(address indexed beneficiary, uint256 amount, uint256 duration);
    event VestingClaimed(address indexed beneficiary, uint256 amount);

    constructor(address treasury)
        ERC20("VIGIL", "VIGIL")
        ERC20Permit("VIGIL")
    {
        require(treasury != address(0), "Invalid treasury");

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);

        // 40% to treasury for ecosystem distribution
        _mint(treasury, INITIAL_SUPPLY);
    }

    /// @notice Mint new tokens (subject to MAX_SUPPLY cap)
    /// @dev Only callable by addresses with MINTER_ROLE
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) nonReentrant {
        require(totalSupply() + amount <= MAX_SUPPLY, "Exceeds max supply");
        _mint(to, amount);
    }

    /// @notice Set up linear vesting for a beneficiary
    /// @dev Tokens must be approved/transferred to this contract first
    function createVesting(
        address beneficiary,
        uint256 amount,
        uint256 duration
    ) external onlyRole(MINTER_ROLE) {
        require(beneficiary != address(0), "Invalid beneficiary");
        require(duration > 0, "Duration must be > 0");

        vestedAmount[beneficiary] += amount;
        vestingStart[beneficiary] = block.timestamp;
        vestingDuration[beneficiary] = duration;

        emit Vested(beneficiary, amount, duration);
    }

    /// @notice Claim vested tokens
    function claimVested() external nonReentrant {
        uint256 vested = _computeVestedAmount(msg.sender);
        uint256 claimable = vested - claimedAmount[msg.sender];
        require(claimable > 0, "Nothing to claim");

        claimedAmount[msg.sender] += claimable;
        _transfer(address(this), msg.sender, claimable);

        emit VestingClaimed(msg.sender, claimable);
    }

    /// @notice Get claimable vested tokens for a beneficiary
    function claimableAmount(address beneficiary) external view returns (uint256) {
        uint256 vested = _computeVestedAmount(beneficiary);
        return vested - claimedAmount[beneficiary];
    }

    function _computeVestedAmount(address beneficiary) internal view returns (uint256) {
        if (vestingDuration[beneficiary] == 0) return 0;

        uint256 elapsed = block.timestamp - vestingStart[beneficiary];
        if (elapsed >= vestingDuration[beneficiary]) {
            return vestedAmount[beneficiary];
        }
        return (vestedAmount[beneficiary] * elapsed) / vestingDuration[beneficiary];
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function _update(address from, address to, uint256 value)
        internal
        override(ERC20, ERC20Permit)
        whenNotPaused
    {
        super._update(from, to, value);
    }
}
