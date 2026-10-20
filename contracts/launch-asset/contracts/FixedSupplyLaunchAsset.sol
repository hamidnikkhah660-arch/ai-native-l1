// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice Separate EVM launch-asset candidate. It is NOT the native Qanvoryx L1 coin.
/// @dev Fixed total supply is minted once at deployment; there is no owner/admin/mint/pause/tax
///      or upgrade function. Allocation recipients can freely transfer their own ERC-20 balances.
///      Do not deploy until allocation addresses, branding, legal review and independent audit
///      are complete. The constructor's name/symbol are deployment inputs and remain subject to
///      trademark/ticker clearance.
contract FixedSupplyLaunchAsset is ERC20 {
    uint256 public constant TOKEN_UNIT = 10 ** 18;
    uint256 public constant MAX_SUPPLY = 10_000_000_000 * TOKEN_UNIT;

    uint256 public constant FOUNDER_ALLOCATION = 4_000_000_000 * TOKEN_UNIT;
    uint256 public constant SECURITY_ALLOCATION = 3_000_000_000 * TOKEN_UNIT;
    uint256 public constant PUBLIC_GOODS_ALLOCATION = 3_000_000_000 * TOKEN_UNIT;

    error ZeroAllocationAddress();
    error DuplicateAllocationAddress();

    constructor(
        string memory name_,
        string memory symbol_,
        address founderTreasury_,
        address securityReserve_,
        address publicGoodsTreasury_
    ) ERC20(name_, symbol_) {
        if (
            founderTreasury_ == address(0) ||
            securityReserve_ == address(0) ||
            publicGoodsTreasury_ == address(0)
        ) revert ZeroAllocationAddress();

        if (
            founderTreasury_ == securityReserve_ ||
            founderTreasury_ == publicGoodsTreasury_ ||
            securityReserve_ == publicGoodsTreasury_
        ) revert DuplicateAllocationAddress();

        // Immediate, visible genesis allocations: these are not time-locked by this contract.
        _mint(founderTreasury_, FOUNDER_ALLOCATION);
        _mint(securityReserve_, SECURITY_ALLOCATION);
        _mint(publicGoodsTreasury_, PUBLIC_GOODS_ALLOCATION);

        assert(totalSupply() == MAX_SUPPLY);
        assert(FOUNDER_ALLOCATION + SECURITY_ALLOCATION + PUBLIC_GOODS_ALLOCATION == MAX_SUPPLY);
    }
}
