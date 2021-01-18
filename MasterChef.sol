pragma solidity ^0.6.12;

import './libraries/IERC20.sol';
import './libraries/SafeMath.sol';
import './libraries/SafeERC20.sol';
import './libraries/IERC20.sol';
import './libraries/IUniswapV2Router02.sol';
import './libraries/UniStakingInterfaces.sol';
import './libraries/IUniswapV2Pair.sol';
import './FODToken.sol';


interface IMigratorChef {
    // Perform LP token migration from legacy UniswapV2 to FODSwap.
    // Take the current LP token address and return the new LP token address.
    // Migrator should have full access to the caller's LP token.
    // Return the new LP token address.
    //
    // XXX Migrator must have allowance access to UniswapV2 LP tokens.
    // FODSwap must mint EXACTLY the same amount of FODSwap LP tokens or
    // else something bad will happen. Traditional UniswapV2 does not
    // do that so be careful!
    function migrate(IERC20 token) external returns (IERC20);
}

// MasterChef is the master of SKULLS. He can make SKULLS and he is a fair guy.
//
// Note that it's ownable and the owner wields tremendous power. The ownership
// will be transferred to a governance smart contract once  is sufficiently
// distributed and the community can show to govern itself.
//
// Have fun reading it. Hopefully it's bug-free. God bless.
contract MasterChef is Ownable {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    // Info of each user.
    struct UserInfo {
        uint256 amount;     // How many LP tokens the user has provided.
        uint256 rewardDebt; // Reward debt. See explanation below.
        //
        // We do some fancy math here. Basically, any point in time, the amount of SKULLSs
        // entitled to a user but is pending to be distributed is:
        //
        //   pending reward = (user.amount * pool.accSKULLSsPerShare) - user.rewardDebt
        //
        // Whenever a user deposits or withdraws LP tokens to a pool. Here's what happens:
        //   1. The pool's `accSKULLSsPerShare` (and `lastRewardBlock`) gets updated.
        //   2. User receives the pending reward sent to his/her address.
        //   3. User's `amount` gets updated.
        //   4. User's `rewardDebt` gets updated.
    }

    // Info of each pool.
    struct PoolInfo {
        IERC20 lpToken;           // Address of LP token contract.
        uint256 allocPoint;       // How many allocation points assigned to this pool. SKULLSs to distribute per block.
        uint256 lastRewardBlock;  // Last block number that SKULLSs distribution occurs.
        uint256 accSKULLSsPerShare; // Accumulated SKULLSs per share, times 1e12. See below.
    }

    // The SKULLS TOKEN!
    FODToken public skulls;
    // Dev address.
    address public devaddr;
    // Block number when bonus SKULLS period ends.
    uint256 public bonusEndBlock;
    // SKULLS tokens created per block.
    uint256 public skullsPerBlock = 5*10**18;
    // Bonus muliplier for early skulls makers.
    uint256 public constant BONUS_MULTIPLIER = 10;
    // The migrator contract. It has a lot of power. Can only be set through governance (owner).
    IMigratorChef public migrator;

    // Info of each pool.
    PoolInfo[] public poolInfo;
    // Info of each user that stakes LP tokens.
    mapping (uint256 => mapping (address => UserInfo)) public userInfo;
    // Total allocation poitns. Must be the sum of all allocation points in all pools.
    uint256 public totalAllocPoint = 0;
    // The block number when SKULLS mining starts.
    uint256 public startBlock;
    
    // initial value of teamrewards
    uint256 public teamRewardsrate = 300;// 10%
    
    // Max value of tokenperblock
    uint256 public constant maxtokenperblock = 10*10**18;// 1 token
    // Max value of teamrewards
    uint256 public constant maxteamRewardsrate = 1000;// 10%
    
    // The WETH Token
    IERC20 internal weth;
    // The Uniswap v2 Router
    IUniswapV2Router02 internal uniswapRouter = IUniswapV2Router02(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
    // The address of the SKULLS-ETH Uniswap pool
    address public skullsPoolAddress;
    
    // Timer variables for globalDecay
    uint256 public timestart = 0;
    uint256 public timeend = now;
    
    // Event logs
    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event SkullsBuyback(address indexed user, uint256 ethSpentOnSKULLS, uint256 skullsBought);

    constructor(
        FODToken _skulls,
        address _devaddr,
        uint256 _skullsPerBlock,
        uint256 _startBlock,
        uint256 _bonusEndBlock
    ) public {
        skulls = _skulls;
        devaddr = _devaddr;
        skullsPerBlock = _skullsPerBlock;
        bonusEndBlock = _bonusEndBlock;
        startBlock = _startBlock;
        
        weth = IERC20(uniswapRouter.WETH());
        
        // Calculate the address the SKULLS-ETH Uniswap pool will exist at
        address uniswapfactoryAddress = uniswapRouter.factory();
        address skullsAddress = address(skulls);
        address wethAddress = address(weth);
        
        // token0 must be strictly less than token1 by sort order to determine the correct address
        (address token0, address token1) = skullsAddress < wethAddress ? (skullsAddress, wethAddress) : (wethAddress, skullsAddress);
        
        skullsPoolAddress = address(uint(keccak256(abi.encodePacked(
            hex'ff',
            uniswapfactoryAddress,
            keccak256(abi.encodePacked(token0, token1)),
            hex'96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f'
        ))));

    }
    
    
    receive() external payable {}
    
    // Internal function that buys back SKULLS with the amount of ETH specified
    //function _buySkulls(uint256 _amount) internal returns (uint256 skullsBought) {
    function _buySkulls(uint256 _amount) public returns (uint256 skullsBought) {
        uint256 ethBalance = address(this).balance;
        if (_amount > ethBalance) _amount = ethBalance;
        if (_amount > 0) {
            uint256 deadline = block.timestamp + 5 minutes;
            address[] memory skullsPath = new address[](2);
            skullsPath[0] = address(weth);
            skullsPath[1] = address(skulls);
            uint256[] memory amounts = uniswapRouter.swapExactETHForTokens{value: _amount}(0, skullsPath, address(this), deadline);
            skullsBought = amounts[1];
        }
        if (skullsBought > 0) emit SkullsBuyback(msg.sender, _amount, skullsBought);
    }
    
    //
    function _addLP(IERC20 _token, IERC20 _pool, uint256 _tokens, uint256 _eth) internal returns (uint256 liquidityAdded) {
        require(_tokens > 0 && _eth > 0);

        IUniswapV2Pair _pair = IUniswapV2Pair(address(_pool));
        (uint256 _reserve0, uint256 _reserve1, ) = _pair.getReserves();
        bool _isToken0 = _pair.token0() == address(_token);
        uint256 _tokensPerETH = 1e18 * (_isToken0 ? _reserve0 : _reserve1) / (_isToken0 ? _reserve1 : _reserve0);

        _token.safeApprove(address(uniswapRouter), 0);
        if (_tokensPerETH > 1e18 * _tokens / _eth) {
            uint256 _ethValue = 1e18 * _tokens / _tokensPerETH;
            _token.safeApprove(address(uniswapRouter), _tokens);
            ( , , liquidityAdded) = uniswapRouter.addLiquidityETH{value: _ethValue}(address(_token), _tokens, 0, 0, address(this), block.timestamp + 5 minutes);
        } else {
            uint256 _tokenValue = 1e18 * _tokensPerETH / _eth;
            _token.safeApprove(address(uniswapRouter), _tokenValue);
            ( , , liquidityAdded) = uniswapRouter.addLiquidityETH{value: _eth}(address(_token), _tokenValue, 0, 0, address(this), block.timestamp + 5 minutes);
        }
        
    }
    
    //
    function _convertToLP(IERC20 _token, IERC20 _pool, uint256 _amount) internal returns (uint256) {
        require(_amount > 0);

        address[] memory _poolPath = new address[](2);
        _poolPath[0] =  uniswapRouter.WETH();
        _poolPath[1] = address(_token);
        uniswapRouter.swapExactETHForTokens{value: _amount / 2}(0, _poolPath, address(this), block.timestamp + 5 minutes);

        return _addLP(_token, _pool, _token.balanceOf(address(this)), address(this).balance);
    }
    
    
    //
    function depositInto(uint256 _pid) external payable {
        require(msg.value > 0);
        
        IERC20 _pool = poolInfo[_pid].lpToken;
        
        uint256 lpReceived = _convertToLP(skulls, _pool, msg.value);
        _pool.safeApprove(address(this), 0);
        _pool.safeApprove(address(this), lpReceived);
        //deposit(_pid, lpReceived);
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        updatePool(_pid);
        if (user.amount > 0) {
            uint256 pending = user.amount.mul(pool.accSKULLSsPerShare).div(1e12).sub(user.rewardDebt);
            safeSkullsTransfer(msg.sender, pending);
        }
        //pool.lpToken.safeTransferFrom(address(msg.sender), address(this), _amount);
        user.amount = user.amount.add(lpReceived);
        user.rewardDebt = user.amount.mul(pool.accSKULLSsPerShare).div(1e12);
        emit Deposit(msg.sender, _pid, lpReceived);
    }

    function poolLength() external view returns (uint256) {
        return poolInfo.length;
    }

    // Add a new lp to the pool. Can only be called by the owner.
    // XXX DO NOT add the same LP token more than once. Rewards will be messed up if you do.
    function add(uint256 _allocPoint, IERC20 _lpToken, bool _withUpdate) public onlyOwner {
        if (_withUpdate) {
            massUpdatePools();
        }
        uint256 lastRewardBlock = block.number > startBlock ? block.number : startBlock;
        totalAllocPoint = totalAllocPoint.add(_allocPoint);
        poolInfo.push(PoolInfo({
            lpToken: _lpToken,
            allocPoint: _allocPoint,
            lastRewardBlock: lastRewardBlock,
            accSKULLSsPerShare: 0
        }));
    }

    // Update the given pool's SKULLS allocation point. Can only be called by the owner.
    function set(uint256 _pid, uint256 _allocPoint, bool _withUpdate) public onlyOwner {
        if (_withUpdate) {
            massUpdatePools();
        }
        totalAllocPoint = totalAllocPoint.sub(poolInfo[_pid].allocPoint).add(_allocPoint);
        poolInfo[_pid].allocPoint = _allocPoint;
    }

    // Set the migrator contract. Can only be called by the owner.
    function setMigrator(IMigratorChef _migrator) public onlyOwner {
        migrator = _migrator;
    }

    // Migrate lp token to another lp contract. Can be called by anyone. We trust that migrator contract is good.
    function migrate(uint256 _pid) public {
        require(address(migrator) != address(0), "migrate: no migrator");
        PoolInfo storage pool = poolInfo[_pid];
        IERC20 lpToken = pool.lpToken;
        uint256 bal = lpToken.balanceOf(address(this));
        lpToken.safeApprove(address(migrator), bal);
        IERC20 newLpToken = migrator.migrate(lpToken);
        require(bal == newLpToken.balanceOf(address(this)), "migrate: bad");
        pool.lpToken = newLpToken;
    }

    // Return reward multiplier over the given _from to _to block.
    function getMultiplier(uint256 _from, uint256 _to) public view returns (uint256) {
        if (_to <= bonusEndBlock) {
            return _to.sub(_from).mul(BONUS_MULTIPLIER);
        } else if (_from >= bonusEndBlock) {
            return _to.sub(_from);
        } else {
            return bonusEndBlock.sub(_from).mul(BONUS_MULTIPLIER).add(
                _to.sub(bonusEndBlock)
            );
        }
    }

    // View function to see pending SKULLSs on frontend.
    function pendingSkulls(uint256 _pid, address _user) external view returns (uint256) {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_user];
        uint256 accSKULLSsPerShare = pool.accSKULLSsPerShare;
        uint256 lpSupply = pool.lpToken.balanceOf(address(this));
        if (block.number > pool.lastRewardBlock && lpSupply != 0) {
            uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
            uint256 skullsReward = multiplier.mul(skullsPerBlock).mul(pool.allocPoint).div(totalAllocPoint);
            accSKULLSsPerShare = accSKULLSsPerShare.add(skullsReward.mul(1e12).div(lpSupply));
        }
        return user.amount.mul(accSKULLSsPerShare).div(1e12).sub(user.rewardDebt);
    }

    // Update reward vairables for all pools. Be careful of gas spending!
    function massUpdatePools() public {
        uint256 length = poolInfo.length;
        for (uint256 pid = 0; pid < length; ++pid) {
            updatePool(pid);
        }
    }

    // Update reward variables of the given pool to be up-to-date.
    function updatePool(uint256 _pid) public {
        PoolInfo storage pool = poolInfo[_pid];
        if (block.number <= pool.lastRewardBlock) {
            return;
        }
        uint256 lpSupply = pool.lpToken.balanceOf(address(this));
        if (lpSupply == 0) {
            pool.lastRewardBlock = block.number;
            return;
        }
        uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
        uint256 skullsReward = multiplier.mul(skullsPerBlock).mul(pool.allocPoint).div(totalAllocPoint);
        skulls.mint(devaddr, skullsReward.div(10000).mul(teamRewardsrate));
        skulls.mint(address(this), skullsReward);
        pool.accSKULLSsPerShare = pool.accSKULLSsPerShare.add(skullsReward.mul(1e12).div(lpSupply));
        pool.lastRewardBlock = block.number;
    }

    // Deposit LP tokens to MasterChef for SKULLS allocation.
    function deposit(uint256 _pid, uint256 _amount) public {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        updatePool(_pid);
        if (user.amount > 0) {
            uint256 pending = user.amount.mul(pool.accSKULLSsPerShare).div(1e12).sub(user.rewardDebt);
            safeSkullsTransfer(msg.sender, pending);
        }
        pool.lpToken.safeTransferFrom(address(msg.sender), address(this), _amount);
        user.amount = user.amount.add(_amount);
        user.rewardDebt = user.amount.mul(pool.accSKULLSsPerShare).div(1e12);
        emit Deposit(msg.sender, _pid, _amount);
    }

    // Withdraw LP tokens from MasterChef.
    function withdraw(uint256 _pid, uint256 _amount) public {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        require(user.amount >= _amount, "withdraw: not good");
        updatePool(_pid);
        uint256 pending = user.amount.mul(pool.accSKULLSsPerShare).div(1e12).sub(user.rewardDebt);
        safeSkullsTransfer(msg.sender, pending);
        user.amount = user.amount.sub(_amount);
        user.rewardDebt = user.amount.mul(pool.accSKULLSsPerShare).div(1e12);
        pool.lpToken.safeTransfer(address(msg.sender), _amount);
        emit Withdraw(msg.sender, _pid, _amount);
    }

    // Withdraw without caring about rewards. EMERGENCY ONLY.
    function emergencyWithdraw(uint256 _pid) public {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        pool.lpToken.safeTransfer(address(msg.sender), user.amount);
        emit EmergencyWithdraw(msg.sender, _pid, user.amount);
        user.amount = 0;
        user.rewardDebt = 0;
    }

    // Safe skulls transfer function, just in case if rounding error causes pool to not have enough SKULLSs.
    function safeSkullsTransfer(address _to, uint256 _amount) internal {
        uint256 skullsBal = skulls.balanceOf(address(this));
        if (_amount > skullsBal) {
            skulls.transfer(_to, skullsBal);
        } else {
            skulls.transfer(_to, _amount);
        }
    }

    // Update dev address by the previous dev.
    function dev(address _devaddr) public {
        require(msg.sender == devaddr, "dev: wut?");
        devaddr = _devaddr;
    }
    
    // globalDecay function
    function globalDecay() public {
        timeend = now;
        uint256 timeinterval = timeend.sub(timestart);
        require(timeinterval > 21600, "timelimit-6hours is not finished yet");
        
        uint256 totaltokenamount = skulls.totalSupply(); 
        totaltokenamount = totaltokenamount.sub(totaltokenamount.mod(1000));
        uint256 decaytokenvalue = totaltokenamount.div(1000);//1% of 10%decayvalue
        
        skulls.globalDecay();
        skulls.mint(msg.sender, decaytokenvalue);
        
        timestart = now;
        
    }
    
    // burn function
    function burn(address account, uint256 amount) public onlyOwner {
        skulls._burn(account, amount);
    }
    
    //change the TPB(tokensPerBlock)
    function changetokensPerBlock(uint256 _newTPB) public onlyOwner {
        require(_newTPB <= maxtokenperblock, "too high value");
        skullsPerBlock = _newTPB;
    }
    
    //change the TBR(transBurnRate)
    function changetransBurnrate(uint256 _newtransBurnrate) public onlyOwner returns (bool) {
        skulls.changetransBurnrate(_newtransBurnrate);
        return true;
    }
    
    //change the DBR(decayBurnrate)
    function changedecayBurnrate(uint256 _newdecayBurnrate) public onlyOwner returns (bool) {
        skulls.changedecayBurnrate(_newdecayBurnrate);
        return true;
    }
    
    //change the TRR(teamRewardsRate)
    function changeteamRewardsrate(uint256 _newTRR) public onlyOwner {
        require(_newTRR <= maxteamRewardsrate, "too high value");
        teamRewardsrate = _newTRR;
    }
}