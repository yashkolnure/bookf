const express = require('express');
const router = express.Router();
const Coupon = require('../models/Coupon');
const Store = require('../models/Store');
const { protect } = require('../middleware/auth');

// @POST /api/coupons/validate — Public: validate coupon at checkout
router.post('/validate', async (req, res) => {
  try {
    const { code, storeId, amount } = req.body;
    const coupon = await Coupon.findOne({
      store: storeId,
      code: code.toUpperCase(),
      isActive: true
    });

    if (!coupon) return res.status(404).json({ success: false, message: 'Coupon not found' });
    if (coupon.expiresAt && coupon.expiresAt < new Date()) {
      return res.status(400).json({ success: false, message: 'Coupon has expired' });
    }
    if (coupon.usageLimit && coupon.usedCount >= coupon.usageLimit) {
      return res.status(400).json({ success: false, message: 'Coupon usage limit reached' });
    }
    if (amount < coupon.minOrderAmount) {
      return res.status(400).json({
        success: false,
        message: `Minimum order amount is ${coupon.minOrderAmount}`
      });
    }

    let discount = 0;
    if (coupon.type === 'percentage') {
      discount = (amount * coupon.value) / 100;
      if (coupon.maxDiscount) discount = Math.min(discount, coupon.maxDiscount);
    } else {
      discount = coupon.value;
    }
    discount = Math.min(discount, amount);

    res.json({
      success: true,
      coupon: { code: coupon.code, type: coupon.type, value: coupon.value, description: coupon.description },
      discountAmount: discount,
      finalAmount: amount - discount
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @GET /api/coupons — Provider: list own coupons
router.get('/', protect, async (req, res) => {
  try {
    const store = await Store.findOne({ owner: req.user._id });
    const coupons = await Coupon.find({ store: store._id }).sort('-createdAt');
    res.json({ success: true, coupons });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @POST /api/coupons — Provider: create coupon
router.post('/', protect, async (req, res) => {
  try {
    const store = await Store.findOne({ owner: req.user._id });
    const coupon = await Coupon.create({ ...req.body, store: store._id });
    res.status(201).json({ success: true, coupon });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({ success: false, message: 'Coupon code already exists in this store' });
    }
    res.status(500).json({ success: false, message: err.message });
  }
});

// @PUT /api/coupons/:id — Provider: update coupon
router.put('/:id', protect, async (req, res) => {
  try {
    const store = await Store.findOne({ owner: req.user._id });
    const coupon = await Coupon.findOneAndUpdate(
      { _id: req.params.id, store: store._id },
      req.body,
      { new: true }
    );
    if (!coupon) return res.status(404).json({ success: false, message: 'Coupon not found' });
    res.json({ success: true, coupon });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @DELETE /api/coupons/:id — Provider: delete coupon
router.delete('/:id', protect, async (req, res) => {
  try {
    const store = await Store.findOne({ owner: req.user._id });
    await Coupon.findOneAndDelete({ _id: req.params.id, store: store._id });
    res.json({ success: true, message: 'Coupon deleted' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;