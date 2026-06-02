// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title VIGIL Staking
/// @notice Stake $VIGIL to unlock premium features and earn protocol rewards
contract VigilStaking is ReentrancyGuard, Ownable {
    using SafeERC20 for IERC20;

    IERC20 public immutable vigilToken;

    // Staking tiers
    struct Tier {
        uint256 minStake;       // Minimum tokens staked (18 decimals)
        string  name;           // Tier name
        uint256 scanQuota;      // Premium scans per day
        uint256 revokeQuota;    // Batch revokes per day
        uint256 rewardBps;      // Reward basis points (e.g., 500 = 5%)
    }

    Tier[] public tiers;

    // Staker data
    struct StakerInfo {
        uint256 amount;
        uint256 stakedAt;
        uint256 lastClaimAt;
        uint256 totalRewardsClaimed;
        uint256 scamReportsVerified;
    }

    mapping(address => StakerInfo) public stakers;

    // Protocol revenue for rewards
    uint256 public rewardPool;
    uint256 public totalStaked;
    uint256 public rewardRate; // Rewards per token per second (scaled 1e18)

    // Scam report bounties
    uint256 public constant SCAM_REPORT_BOUNTY = 50 * 1e18; // 50 VIGIL per verified report

    event Staked(address indexed user, uint256 amount);
    event Unstaked(address indexed user, uint256 amount);
    event RewardsClaimed(address indexed user, uint256 amount);
    event ScamReportVerified(address indexed reporter, uint256 bounty);
    event RewardPoolFunded(uint256 amount);

    constructor(address _vigilToken, address _owner) Ownable(_owner) {
        require(_vigilToken != address(0), "Invalid token");
        vigilToken = IERC20(_vigilToken);

        // Initialize tiers
        tiers.push(Tier({
            minStake: 100 * 1e18,       // 100 VIGIL
            name: "Scout",
            scanQuota: 50,
            revokeQuota: 10,
            rewardBps: 200               // 2%
        }));
        tiers.push(Tier({
            minStake: 500 * 1e18,        // 500 VIGIL
            name: "Guardian",
            scanQuota: 200,
            revokeQuota: 50,
            rewardBps: 500               // 5%
        }));
        tiers.push(Tier({
            minStake: 1000 * 1e18,       // 1,000 VIGIL
            name: "Sentinel",
            scanQuota: 999999,           // Unlimited
            revokeQuota: 999999,         // Unlimited
            rewardBps: 800               // 8%
        }));
        tiers.push(Tier({
            minStake: 5000 * 1e18,       // 5,000 VIGIL
            name: "Archon",
            scanQuota: 999999,           // Unlimited
            revokeQuota: 999999,         // Unlimited
            rewardBps: 1200              // 12%
        }));
    }

    /// @notice Stake VIGIL tokens
    function stake(uint256 amount) external nonReentrant {
        require(amount > 0, "Amount must be > 0");

        vigilToken.safeTransferFrom(msg.sender, address(this), amount);

        stakers[msg.sender].amount += amount;
        stakers[msg.sender].stakedAt = block.timestamp;
        totalStaked += amount;

        emit Staked(msg.sender, amount);
    }

    /// @notice Unstake VIGIL tokens
    function unstake(uint256 amount) external nonReentrant {
        require(stakers[msg.sender].amount >= amount, "Insufficient stake");

        // Auto-claim pending rewards
        uint256 pending = pendingRewards(msg.sender);
        if (pending > 0) {
            _claimRewards(msg.sender, pending);
        }

        stakers[msg.sender].amount -= amount;
        totalStaked -= amount;

        vigilToken.safeTransfer(msg.sender, amount);

        emit Unstaked(msg.sender, amount);
    }

    /// @notice Claim accumulated rewards
    function claimRewards() external nonReentrant {
        uint256 pending = pendingRewards(msg.sender);
        require(pending > 0, "No rewards");

        _claimRewards(msg.sender, pending);
    }

    function _claimRewards(address user, uint256 amount) internal {
        require(rewardPool >= amount, "Insufficient reward pool");

        stakers[user].lastClaimAt = block.timestamp;
        stakers[user].totalRewardsClaimed += amount;
        rewardPool -= amount;

        vigilToken.safeTransfer(user, amount);

        emit RewardsClaimed(user, amount);
    }

    /// @notice Get pending rewards for a staker
    function pendingRewards(address user) public view returns (uint256) {
        StakerInfo memory info = stakers[user];
        if (info.amount == 0) return 0;

        uint256 lastClaim = info.lastClaimAt > 0 ? info.lastClaimAt : info.stakedAt;
        uint256 duration = block.timestamp - lastClaim;

        uint256 tierRewardBps = _getTier(info.amount).rewardBps;
        uint256 baseReward = (info.amount * rewardRate * duration) / 1e18;
        uint256 tierBonus = (baseReward * tierRewardBps) / 10000;

        return baseReward + tierBonus;
    }

    /// @notice Fund the reward pool (called by protocol revenue)
    function fundRewards(uint256 amount) external onlyOwner {
        require(amount > 0, "Amount must be > 0");
        vigilToken.safeTransferFrom(msg.sender, address(this), amount);
        rewardPool += amount;

        // Recalculate reward rate
        if (totalStaked > 0) {
            rewardRate = (rewardPool * 1e18) / (totalStaked * 365 days);
        }

        emit RewardPoolFunded(amount);
    }

    /// @notice Record a verified scam report and pay bounty
    function recordScamReport(address reporter) external onlyOwner {
        stakers[reporter].scamReportsVerified++;
        require(rewardPool >= SCAM_REPORT_BOUNTY, "Insufficient bounty pool");

        rewardPool -= SCAM_REPORT_BOUNTY;
        vigilToken.safeTransfer(reporter, SCAM_REPORT_BOUNTY);

        emit ScamReportVerified(reporter, SCAM_REPORT_BOUNTY);
    }

    /// @notice Get staker's tier
    function getStakerTier(address user) external view returns (
        string memory name,
        uint256 scanQuota,
        uint256 revokeQuota,
        uint256 rewardBps
    ) {
        Tier memory tier = _getTier(stakers[user].amount);
        return (tier.name, tier.scanQuota, tier.revokeQuota, tier.rewardBps);
    }

    /// @notice Get all tiers
    function getTiers() external view returns (Tier[] memory) {
        return tiers;
    }

    /// @notice Get staker info
    function getStakerInfo(address user) external view returns (StakerInfo memory) {
        return stakers[user];
    }

    function _getTier(uint256 stakeAmount) internal view returns (Tier memory) {
        // Return highest tier the staker qualifies for
        for (uint256 i = tiers.length; i > 0; i--) {
            if (stakeAmount >= tiers[i - 1].minStake) {
                return tiers[i - 1];
            }
        }
        return tiers[0]; // Default to lowest tier
    }
}
