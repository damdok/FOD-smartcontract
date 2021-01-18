pragma solidity ^0.6.12;

import './libraries/IERC20.sol';
import './libraries/Ownable.sol';
import './libraries/Address.sol';
import './libraries/SafeMath.sol';

interface Callable {
    function tokenCallback(address _from, uint256 _tokens, bytes calldata _data) external returns (bool);
    function receiveApproval(address _from, uint256 _tokens, address _token, bytes calldata _data) external;
}

contract FODToken is Context, IERC20, Ownable {
    using SafeMath for uint256;
    using Address for address;
    
    event LogBurn(uint256 decayrate, uint256 totalSupply);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    modifier validRecipient(address to) {
        require(to != address(0x0));
        require(to != address(this));
        _;
    }

    string public constant _name = "Farm Or Die";
    string public constant _symbol = "SKULLS";
    uint8 public _decimals = 18;
    
    uint256 private constant DECIMALS = 18;
    uint256 private constant MAX_UINT256 = ~uint256(0); //(2^256) - 1
    uint256 private constant INITIAL_FRAGMENTS_SUPPLY = 27000 * 10**DECIMALS;
    uint256 private constant TOTAL_GONS = MAX_UINT256 - (MAX_UINT256 % INITIAL_FRAGMENTS_SUPPLY);
    uint256 private constant MAX_SUPPLY = ~uint128(0); //(2^128) - 1
    
    uint256 private constant max_supply = 100000 * 10**DECIMALS;
    bool public maxSupplyHit = false;
    
    // The MasterChef contract
    address public masterchefAddress;
    // The Uniswap SKULLS-ETH LP token address
    address public skullsPoolAddress;
   
    uint256 private _totalSupply;
    uint256 private _gonsPerFragment;
    mapping(address => uint256) private _gonBalances;
    mapping (address => mapping (address => uint256)) private _allowedFragments;
   
    uint256 public transBurnrate = 250; //initial 2.5%
    
    uint256 public decayBurnrate = 500; //initial 5%
    
    uint256 public maxtransBurnrate = 1000; // max 10%
    
    uint256 public maxdecayBurnrate = 1000; // max 10%
    
    
    // @notice A record of each accounts delegate
    mapping (address => address) internal _delegates;
    // @notice A checkpoint for marking number of votes from a given block
    struct Checkpoint {
        uint32 fromBlock;
        uint256 votes;
    }
    // @notice A record of votes checkpoints for each account, by index
    mapping (address => mapping (uint32 => Checkpoint)) public checkpoints;
    // @notice The number of checkpoints for each account
    mapping (address => uint32) public numCheckpoints;
    // @notice The EIP-712 typehash for the contract's domain
    bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
    // @notice The EIP-712 typehash for the delegation struct used by the contract
    bytes32 public constant DELEGATION_TYPEHASH = keccak256("Delegation(address delegatee,uint256 nonce,uint256 expiry)");
    // @notice A record of states for signing / validating signatures
    mapping (address => uint) public nonces;
    // @notice An event thats emitted when an account changes its delegate
    event DelegateChanged(address indexed delegator, address indexed fromDelegate, address indexed toDelegate);
    // @notice An event thats emitted when a delegate account's vote balance changes
    event DelegateVotesChanged(address indexed delegate, uint previousBalance, uint newBalance);

   

    constructor() public {
        _owner = msg.sender;
        
        _totalSupply = INITIAL_FRAGMENTS_SUPPLY;
        _gonBalances[_owner] = TOTAL_GONS;
        _gonsPerFragment = TOTAL_GONS.div(_totalSupply);

        emit Transfer(address(0x0), _owner, _totalSupply);
    }
    
    function globalDecay() public onlyOwner returns (uint256)
    {
        uint256 _remainrate = 10000; //0.25%->decayrate=25
        _remainrate = _remainrate.sub(decayBurnrate);


        _totalSupply = _totalSupply.mul(_remainrate);
        _totalSupply = _totalSupply.sub(_totalSupply.mod(10000));
        _totalSupply = _totalSupply.div(10000);

        
        if (_totalSupply > MAX_SUPPLY) {
            _totalSupply = MAX_SUPPLY;
        }

        _gonsPerFragment = TOTAL_GONS.div(_totalSupply);

        emit LogBurn(decayBurnrate, _totalSupply);
        return _totalSupply;
    }
    
    function _burn(address account, uint256 amount) public onlyOwner {
        require(account != address(0), "burn from the zero address");

        _beforeTokenTransfer(account, address(0), amount);
        
        uint256 gonValue = amount.mul(_gonsPerFragment);
        _gonBalances[account] = _gonBalances[account].sub(gonValue, "burn amount exceeds balance");
        
        _totalSupply = _totalSupply.sub(amount, "burn amount exceeds balance");
        emit Transfer(account, address(0), amount);
    }
    
    
    function name() public pure returns (string memory) {
        return _name;
    }
    
    function symbol() public pure returns (string memory) {
        return _symbol;
    }
    
    function decimals() public view override returns (uint8) {
        return _decimals;
    }
    
    function totalSupply() public view override returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) public view override returns (uint256)
    {
        return _gonBalances[account].div(_gonsPerFragment);
    }
    
    function transfer(address to, uint256 value) public validRecipient(to) virtual override returns (bool)
    {
        uint256 gonValue = value.mul(_gonsPerFragment);
        _gonBalances[msg.sender] = _gonBalances[msg.sender].sub(gonValue);
        _gonBalances[to] = _gonBalances[to].add(gonValue);
        emit Transfer(msg.sender, to, value);
        return true;
    }
    
    function allowance(address owner_, address spender) public view virtual override returns (uint256)
    {
        return _allowedFragments[owner_][spender];
    }

    function approve(address spender, uint256 value) public virtual override returns (bool)
    {
        _allowedFragments[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }
    
    function transferFrom(address from, address to, uint256 value) public validRecipient(to) virtual override returns (bool)
    {
       _allowedFragments[from][msg.sender] = _allowedFragments[from][msg.sender].sub(value);

        uint256 gonValue = value.mul(_gonsPerFragment);
        _gonBalances[from] = _gonBalances[from].sub(gonValue);
        _gonBalances[to] = _gonBalances[to].add(gonValue);
        emit Transfer(from, to, value);

        return true;
    }
    
    function increaseAllowance(address spender, uint256 addedValue) public returns (bool)
    {
        _allowedFragments[msg.sender][spender] =
        _allowedFragments[msg.sender][spender].add(addedValue);
        emit Approval(msg.sender, spender, _allowedFragments[msg.sender][spender]);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public returns (bool)
    {
        uint256 oldValue = _allowedFragments[msg.sender][spender];
        if (subtractedValue >= oldValue) {
            _allowedFragments[msg.sender][spender] = 0;
        } else {
            _allowedFragments[msg.sender][spender] = oldValue.sub(subtractedValue);
        }
        emit Approval(msg.sender, spender, _allowedFragments[msg.sender][spender]);
        return true;
    }
    
    function changetransBurnrate(uint256 _newtransBurnrate) public onlyOwner returns (bool) {
        require(_newtransBurnrate <= maxtransBurnrate, "too high value");
        transBurnrate = _newtransBurnrate;
        return true;
    }
    
    function changedecayBurnrate(uint256 _newdecayBurnrate) public onlyOwner returns (bool) {
        require(_newdecayBurnrate <= maxdecayBurnrate, "too high value");
        decayBurnrate = _newdecayBurnrate;
        return true;
    }

    function mint(address account, uint256 amount) public onlyOwner {
        require(account != address(0));
        require(maxSupplyHit != true, "max supply hit");
        
        uint256 supply = totalSupply();
        if (supply.add(amount) >= max_supply) {
            amount = max_supply.sub(supply);
            maxSupplyHit = true;
        }
        
        _beforeTokenTransfer(address(0), account, amount);
        uint256 gonValue = amount.mul(_gonsPerFragment);

        _totalSupply = _totalSupply.add(amount);
        _gonBalances[account] = _gonBalances[account].add(gonValue);
        emit Transfer(address(0), account, amount);
        
        _moveDelegates(address(0), _delegates[account], amount);
    }
   
    
    /**
     * @dev Hook that is called before any transfer of tokens. This includes
     * minting and burning.
     *
     * Calling conditions:
     *
     * - when `from` and `to` are both non-zero, `amount` of ``from``'s tokens
     * will be to transferred to `to`.
     * - when `from` is zero, `amount` tokens will be minted for `to`.
     * - when `to` is zero, `amount` of ``from``'s tokens will be burned.
     * - `from` and `to` are never both zero.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual { }
    
    function approveAndCall(address _spender, uint256 _tokens, bytes calldata _data) external returns (bool) {
        approve(_spender, _tokens);
        Callable(_spender).receiveApproval(msg.sender, _tokens, address(this), _data);
        return true;
    }

    function transferAndCall(address _to, uint256 _tokens, bytes calldata _data) external returns (bool) {
        uint256 _balanceBefore = balanceOf(_to);
        transfer(_to, _tokens);
        uint256 _tokensReceived = balanceOf(_to) - _balanceBefore;
        uint32 _size;
        assembly {
            _size := extcodesize(_to)
        }
        if (_size > 0) {
            require(Callable(_to).tokenCallback(msg.sender, _tokensReceived, _data));
        }
        return true;
    }
    
    // Both the MasterChef contracts will lock the SKULLS-ETH LP tokens they receive from their staking/unstaking fees here (ensuring liquidity forever).
    // This function allows SKULLS token holders to decide what to do with the locked LP tokens in the future
    function migrateLockedLPTokens(address _to, uint256 _amount) public onlyOwner {
        IERC20 skullsPool = IERC20(skullsPoolAddress);
        require(_amount > 0 && _amount <= skullsPool.balanceOf(address(this)), "bad amount");
        skullsPool.transfer(_to, _amount);
    }
    
    // Sets the addresses of the MasterChef farming contract, and the Uniswap SKULLS-ETH LP token
    function setContractAddresses(address _masterchefAddress, address _skullsPoolAddress) public onlyOwner {
        if (_masterchefAddress != address(0)) masterchefAddress = _masterchefAddress;
        if (_skullsPoolAddress != address(0)) skullsPoolAddress = _skullsPoolAddress;
    }

    /**
     * @notice Delegate votes from `msg.sender` to `delegatee`
     * @param delegator The address to get delegatee for
     */
    function delegates(address delegator) external view returns (address) {
        return _delegates[delegator];
    }

   /**
    * @notice Delegate votes from `msg.sender` to `delegatee`
    * @param delegatee The address to delegate votes to
    */
    function delegate(address delegatee) external {
        return _delegate(msg.sender, delegatee);
    }

    /**
     * @notice Delegates votes from signatory to `delegatee`
     * @param delegatee The address to delegate votes to
     * @param nonce The contract state required to match the signature
     * @param expiry The time at which to expire the signature
     * @param v The recovery byte of the signature
     * @param r Half of the ECDSA signature pair
     * @param s Half of the ECDSA signature pair
     */
    function delegateBySig(address delegatee, uint nonce, uint expiry,  uint8 v, bytes32 r, bytes32 s) external {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(name())),
                getChainId(),
                address(this)
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(
                DELEGATION_TYPEHASH,
                delegatee,
                nonce,
                expiry
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                structHash
            )
        );

        address signatory = ecrecover(digest, v, r, s);
        require(signatory != address(0), "SKULLS::delegateBySig: invalid signature");
        require(nonce == nonces[signatory]++, "SKULLS::delegateBySig: invalid nonce");
        require(now <= expiry, "SKULLS::delegateBySig: signature expired");
        return _delegate(signatory, delegatee);
    }

    /**
     * @notice Gets the current votes balance for `account`
     * @param account The address to get votes balance
     * @return The number of current votes for `account`
     */
    function getCurrentVotes(address account) external view returns (uint256) {
        uint32 nCheckpoints = numCheckpoints[account];
        return nCheckpoints > 0 ? checkpoints[account][nCheckpoints - 1].votes : 0;
    }

    /**
     * @notice Determine the prior number of votes for an account as of a block number
     * @dev Block number must be a finalized block or else this function will revert to prevent misinformation.
     * @param account The address of the account to check
     * @param blockNumber The block number to get the vote balance at
     * @return The number of votes the account had as of the given block
     */
    function getPriorVotes(address account, uint blockNumber) external view returns (uint256) {
        require(blockNumber < block.number, "SKULLS::getPriorVotes: not yet determined");

        uint32 nCheckpoints = numCheckpoints[account];
        if (nCheckpoints == 0) {
            return 0;
        }

        // First check most recent balance
        if (checkpoints[account][nCheckpoints - 1].fromBlock <= blockNumber) {
            return checkpoints[account][nCheckpoints - 1].votes;
        }

        // Next check implicit zero balance
        if (checkpoints[account][0].fromBlock > blockNumber) {
            return 0;
        }

        uint32 lower = 0;
        uint32 upper = nCheckpoints - 1;
        while (upper > lower) {
            uint32 center = upper - (upper - lower) / 2; // ceil, avoiding overflow
            Checkpoint memory cp = checkpoints[account][center];
            if (cp.fromBlock == blockNumber) {
                return cp.votes;
            } else if (cp.fromBlock < blockNumber) {
                lower = center;
            } else {
                upper = center - 1;
            }
        }
        return checkpoints[account][lower].votes;
    }

    function _delegate(address delegator, address delegatee) internal {
        address currentDelegate = _delegates[delegator];
        uint256 delegatorBalance = balanceOf(delegator); // balance of underlying SKULLSs (not scaled);
        _delegates[delegator] = delegatee;

        emit DelegateChanged(delegator, currentDelegate, delegatee);

        _moveDelegates(currentDelegate, delegatee, delegatorBalance);
    }

    function _moveDelegates(address srcRep, address dstRep, uint256 amount) internal {
        if (srcRep != dstRep && amount > 0) {
            if (srcRep != address(0)) {
                // decrease old representative
                uint32 srcRepNum = numCheckpoints[srcRep];
                uint256 srcRepOld = srcRepNum > 0 ? checkpoints[srcRep][srcRepNum - 1].votes : 0;
                uint256 srcRepNew = srcRepOld.sub(amount);
                _writeCheckpoint(srcRep, srcRepNum, srcRepOld, srcRepNew);
            }

            if (dstRep != address(0)) {
                // increase new representative
                uint32 dstRepNum = numCheckpoints[dstRep];
                uint256 dstRepOld = dstRepNum > 0 ? checkpoints[dstRep][dstRepNum - 1].votes : 0;
                uint256 dstRepNew = dstRepOld.add(amount);
                _writeCheckpoint(dstRep, dstRepNum, dstRepOld, dstRepNew);
            }
        }
    }

    function _writeCheckpoint(address delegatee, uint32 nCheckpoints, uint256 oldVotes, uint256 newVotes)  internal  {
        uint32 blockNumber = safe32(block.number, "SKULLS::_writeCheckpoint: block number exceeds 32 bits");

        if (nCheckpoints > 0 && checkpoints[delegatee][nCheckpoints - 1].fromBlock == blockNumber) {
            checkpoints[delegatee][nCheckpoints - 1].votes = newVotes;
        } else {
            checkpoints[delegatee][nCheckpoints] = Checkpoint(blockNumber, newVotes);
            numCheckpoints[delegatee] = nCheckpoints + 1;
        }

        emit DelegateVotesChanged(delegatee, oldVotes, newVotes);
    }

    function safe32(uint n, string memory errorMessage) internal pure returns (uint32) {
        require(n < 2**32, errorMessage);
        return uint32(n);
    }

    function getChainId() internal pure returns (uint) {
        uint256 chainId;
        assembly { chainId := chainid() }
        return chainId;
    }
}