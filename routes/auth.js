const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const Store = require('../models/Store');
const { protect } = require('../middleware/auth');

const generateToken = (id) =>
  jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRE });

// @POST /api/auth/register
//
//
router.post('/register', [
  body('name').trim().notEmpty().withMessage('Name is required'),
  body('email').isEmail().withMessage('Valid email required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  body('storeName').trim().notEmpty().withMessage('Store name is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ success: false, errors: errors.array() });

  const { name, email, password, storeName, storeCategory } = req.body;
  
  try {
    if (await User.findOne({ email })) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    // 1. Create User
    const user = await User.create({ name, email, password, role: 'provider' });

    // 2. Create Store (Subscription defaults are handled by the Store Schema)
    const store = await Store.create({
      owner: user._id,
      name: storeName,
      category: storeCategory || 'other'
    });

    const token = generateToken(user._id);

    // 3. Return Full Response including subscription
    res.status(201).json({
      success: true,
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role },
      store: { 
        id: store._id, 
        name: store.name, 
        slug: store.slug,
        subscription: store.subscription // FIXED: Ensure frontend gets trial info immediately
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── LOGIN ROUTE ───
// @POST /api/auth/login
router.post('/login', [
  body('email').isEmail().withMessage('Valid email required'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ success: false, errors: errors.array() });

  const { email, password } = req.body;
  
  try {
    const user = await User.findOne({ email }).select('+password');
    if (!user || !(await user.matchPassword(password))) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    if (!user.isActive) {
      return res.status(403).json({ success: false, message: 'Account is deactivated' });
    }

    // FIXED: Added 'subscription' to the select string
    const store = await Store.findOne({ owner: user._id })
      .select('name slug _id subscription'); 

    const token = generateToken(user._id);

    res.json({
      success: true,
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role },
      store
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── ME ROUTE (PROFILE & STORE REFRESH) ───
// @GET /api/auth/me
router.get('/me', protect, async (req, res) => {
  try {
    // FIXED: Added 'subscription' to the select string
    const store = await Store.findOne({ owner: req.user._id })
      .select('name slug _id category subscription'); 
    
    res.json({
      success: true,
      user: { 
        id: req.user._id, 
        name: req.user.name, 
        email: req.user.email, 
        role: req.user.role 
      },
      store
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @PUT /api/auth/profile
router.put('/profile', protect, [
  body('name').optional().trim().notEmpty(),
  body('phone').optional()
], async (req, res) => {
  try {
    const { name, phone, avatar } = req.body;
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { name, phone, avatar },
      { new: true, runValidators: true }
    );
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @PUT /api/auth/password
router.put('/password', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('+password');
    if (!(await user.matchPassword(req.body.currentPassword))) {
      return res.status(400).json({ success: false, message: 'Current password is incorrect' });
    }
    user.password = req.body.newPassword;
    await user.save();
    res.json({ success: true, message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;