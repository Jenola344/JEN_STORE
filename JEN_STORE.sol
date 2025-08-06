// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title JenStore
 * @dev Smart contract for JEN_STORE e-commerce platform
 * Handles product management, purchases, and transactions
 */
contract JenStore is ReentrancyGuard, Ownable, Pausable {
    
    // Events
    event ProductAdded(uint256 indexed productId, string name, uint256 price, uint256 stock);
    event ProductUpdated(uint256 indexed productId, uint256 price, uint256 stock);
    event ProductPurchased(
        uint256 indexed productId, 
        address indexed buyer, 
        uint256 quantity, 
        uint256 totalAmount,
        uint256 timestamp
    );
    event PaymentReceived(address indexed from, uint256 amount);
    event FundsWithdrawn(address indexed to, uint256 amount);
    event RefundIssued(address indexed to, uint256 amount, string reason);

    // Structs
    struct Product {
        string name;
        string description;
        uint256 price; // Price in wei
        uint256 stock;
        bool active;
        uint256 totalSold;
    }

    struct Purchase {
        uint256 productId;
        address buyer;
        uint256 quantity;
        uint256 totalAmount;
        uint256 timestamp;
        bool refunded;
    }

    // State variables
    mapping(uint256 => Product) public products;
    mapping(uint256 => Purchase[]) public productPurchases;
    mapping(address => Purchase[]) public userPurchases;
    
    uint256 public productCount;
    uint256 public totalRevenue;
    uint256 public totalTransactions;
    
    // Discount system
    mapping(address => uint256) public discountPercentage; // 0-100
    uint256 public loyaltyThreshold = 5; // Number of purchases for loyalty discount
    uint256 public loyaltyDiscount = 10; // 10% discount for loyal customers

    constructor() {
        // Initialize with JEN_STORE products
        _addProduct("iPhone 15 Pro", "Latest iPhone with titanium design, A17 Pro chip", 1199 ether / 1000, 50); // $1199.99 in wei equivalent
        _addProduct("AirPods Pro", "Wireless earbuds with active noise cancellation", 249 ether / 1000, 100);
        _addProduct("MacBook Air M3", "Ultra-thin laptop with M3 chip, 15-inch display", 1299 ether / 1000, 25);
        _addProduct("Apple Watch Ultra", "Rugged smartwatch with titanium case", 799 ether / 1000, 75);
        _addProduct("iPad Pro 12.9", "Professional tablet with M2 chip", 1099 ether / 1000, 40);
        _addProduct("MagSafe Charger", "Wireless charger with magnetic alignment", 39 ether / 1000, 200);
    }

    /**
     * @dev Add a new product (only owner)
     */
    function addProduct(
        string memory _name,
        string memory _description,
        uint256 _price,
        uint256 _stock
    ) external onlyOwner {
        _addProduct(_name, _description, _price, _stock);
    }

    /**
     * @dev Internal function to add product
     */
    function _addProduct(
        string memory _name,
        string memory _description,
        uint256 _price,
        uint256 _stock
    ) internal {
        products[productCount] = Product({
            name: _name,
            description: _description,
            price: _price,
            stock: _stock,
            active: true,
            totalSold: 0
        });
        
        emit ProductAdded(productCount, _name, _price, _stock);
        productCount++;
    }

    /**
     * @dev Update product details (only owner)
     */
    function updateProduct(
        uint256 _productId,
        uint256 _price,
        uint256 _stock,
        bool _active
    ) external onlyOwner {
        require(_productId < productCount, "Product does not exist");
        
        products[_productId].price = _price;
        products[_productId].stock = _stock;
        products[_productId].active = _active;
        
        emit ProductUpdated(_productId, _price, _stock);
    }

    /**
     * @dev Purchase a product
     */
    function purchaseProduct(uint256 _productId, uint256 _quantity) 
        external 
        payable 
        nonReentrant 
        whenNotPaused 
    {
        require(_productId < productCount, "Product does not exist");
        require(_quantity > 0, "Quantity must be greater than 0");
        
        Product storage product = products[_productId];
        require(product.active, "Product is not active");
        require(product.stock >= _quantity, "Insufficient stock");
        
        uint256 baseTotal = product.price * _quantity;
        uint256 discount = _calculateDiscount(msg.sender, baseTotal);
        uint256 finalTotal = baseTotal - discount;
        
        require(msg.value >= finalTotal, "Insufficient payment");
        
        // Update product stock and sales
        product.stock -= _quantity;
        product.totalSold += _quantity;
        
        // Record purchase
        Purchase memory purchase = Purchase({
            productId: _productId,
            buyer: msg.sender,
            quantity: _quantity,
            totalAmount: finalTotal,
            timestamp: block.timestamp,
            refunded: false
        });
        
        productPurchases[_productId].push(purchase);
        userPurchases[msg.sender].push(purchase);
        
        // Update totals
        totalRevenue += finalTotal;
        totalTransactions++;
        
        // Refund excess payment
        if (msg.value > finalTotal) {
            payable(msg.sender).transfer(msg.value - finalTotal);
        }
        
        emit ProductPurchased(_productId, msg.sender, _quantity, finalTotal, block.timestamp);
        emit PaymentReceived(msg.sender, finalTotal);
    }

    /**
     * @dev Calculate discount for a user
     */
    function _calculateDiscount(address _user, uint256 _amount) internal view returns (uint256) {
        uint256 discount = 0;
        
        // Apply custom discount
        if (discountPercentage[_user] > 0) {
            discount = (_amount * discountPercentage[_user]) / 100;
        }
        
        // Apply loyalty discount
        if (userPurchases[_user].length >= loyaltyThreshold) {
            uint256 loyaltyDiscountAmount = (_amount * loyaltyDiscount) / 100;
            if (loyaltyDiscountAmount > discount) {
                discount = loyaltyDiscountAmount;
            }
        }
        
        return discount;
    }

    /**
     * @dev Batch purchase multiple products
     */
    function batchPurchase(
        uint256[] calldata _productIds,
        uint256[] calldata _quantities
    ) external payable nonReentrant whenNotPaused {
        require(_productIds.length == _quantities.length, "Arrays length mismatch");
        require(_productIds.length > 0, "No products specified");
        
        uint256 totalCost = 0;
        
        // Calculate total cost first
        for (uint256 i = 0; i < _productIds.length; i++) {
            require(_productIds[i] < productCount, "Product does not exist");
            require(_quantities[i] > 0, "Quantity must be greater than 0");
            require(products[_productIds[i]].active, "Product is not active");
            require(products[_productIds[i]].stock >= _quantities[i], "Insufficient stock");
            
            totalCost += products[_productIds[i]].price * _quantities[i];
        }
        
        uint256 discount = _calculateDiscount(msg.sender, totalCost);
        uint256 finalTotal = totalCost - discount;
        require(msg.value >= finalTotal, "Insufficient payment");
        
        // Process each purchase
        for (uint256 i = 0; i < _productIds.length; i++) {
            uint256 productId = _productIds[i];
            uint256 quantity = _quantities[i];
            
            products[productId].stock -= quantity;
            products[productId].totalSold += quantity;
            
            uint256 itemTotal = (products[productId].price * quantity * finalTotal) / totalCost;
            
            Purchase memory purchase = Purchase({
                productId: productId,
                buyer: msg.sender,
                quantity: quantity,
                totalAmount: itemTotal,
                timestamp: block.timestamp,
                refunded: false
            });
            
            productPurchases[productId].push(purchase);
            userPurchases[msg.sender].push(purchase);
            
            emit ProductPurchased(productId, msg.sender, quantity, itemTotal, block.timestamp);
        }
        
        totalRevenue += finalTotal;
        totalTransactions++;
        
        // Refund excess payment
        if (msg.value > finalTotal) {
            payable(msg.sender).transfer(msg.value - finalTotal);
        }
        
        emit PaymentReceived(msg.sender, finalTotal);
    }

    /**
     * @dev Issue refund (only owner)
     */
    function issueRefund(
        address _buyer,
        uint256 _purchaseIndex,
        string calldata _reason
    ) external onlyOwner nonReentrant {
        require(_purchaseIndex < userPurchases[_buyer].length, "Invalid purchase index");
        
        Purchase storage purchase = userPurchases[_buyer][_purchaseIndex];
        require(!purchase.refunded, "Already refunded");
        require(address(this).balance >= purchase.totalAmount, "Insufficient contract balance");
        
        purchase.refunded = true;
        
        // Restore stock
        products[purchase.productId].stock += purchase.quantity;
        products[purchase.productId].totalSold -= purchase.quantity;
        
        // Update totals
        totalRevenue -= purchase.totalAmount;
        
        payable(_buyer).transfer(purchase.totalAmount);
        
        emit RefundIssued(_buyer, purchase.totalAmount, _reason);
    }

    /**
     * @dev Set discount for specific user (only owner)
     */
    function setUserDiscount(address _user, uint256 _percentage) external onlyOwner {
        require(_percentage <= 100, "Discount cannot exceed 100%");
        discountPercentage[_user] = _percentage;
    }

    /**
     * @dev Update loyalty program settings (only owner)
     */
    function updateLoyaltyProgram(uint256 _threshold, uint256 _discount) external onlyOwner {
        require(_discount <= 100, "Discount cannot exceed 100%");
        loyaltyThreshold = _threshold;
        loyaltyDiscount = _discount;
    }

    /**
     * @dev Withdraw contract funds (only owner)
     */
    function withdraw(uint256 _amount) external onlyOwner nonReentrant {
        require(_amount <= address(this).balance, "Insufficient balance");
        payable(owner()).transfer(_amount);
        emit FundsWithdrawn(owner(), _amount);
    }

    /**
     * @dev Emergency withdraw all funds (only owner)
     */
    function emergencyWithdraw() external onlyOwner nonReentrant {
        uint256 balance = address(this).balance;
        payable(owner()).transfer(balance);
        emit FundsWithdrawn(owner(), balance);
    }

    /**
     * @dev Pause contract (only owner)
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @dev Unpause contract (only owner)
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    // View functions
    function getProduct(uint256 _productId) external view returns (Product memory) {
        require(_productId < productCount, "Product does not exist");
        return products[_productId];
    }

    function getUserPurchases(address _user) external view returns (Purchase[] memory) {
        return userPurchases[_user];
    }

    function getProductPurchases(uint256 _productId) external view returns (Purchase[] memory) {
        require(_productId < productCount, "Product does not exist");
        return productPurchases[_productId];
    }

    function calculateTotalCost(uint256 _productId, uint256 _quantity) external view returns (uint256) {
        require(_productId < productCount, "Product does not exist");
        uint256 baseTotal = products[_productId].price * _quantity;
        uint256 discount = _calculateDiscount(msg.sender, baseTotal);
        return baseTotal - discount;
    }

    function getUserDiscount(address _user) external view returns (uint256) {
        return discountPercentage[_user];
    }

    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }

    function isLoyalCustomer(address _user) external view returns (bool) {
        return userPurchases[_user].length >= loyaltyThreshold;
    }

    // Receive function to accept direct payments
    receive() external payable {
        emit PaymentReceived(msg.sender, msg.value);
    }
}
