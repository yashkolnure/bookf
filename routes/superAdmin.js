const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Store = require('../models/Store');
const { superAdminProtect } = require('../middleware/superAdminAuth');

// Plans configuration
const PLANS_CONFIG = {
  free: { name: '7 Day Free Trial', durationDays: 7 },
  quarterly: { name: 'Quarterly (3 Months)', durationDays: 90 },
  halfyearly: { name: 'Half Yearly (6 Months)', durationDays: 180 },
  yearly: { name: 'Yearly (1 Year)', durationDays: 365 },
};

// ─── SUPER ADMIN LOGIN ───
// POST /api/superadmin/login
router.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (
    email !== process.env.SUPER_ADMIN_EMAIL ||
    password !== process.env.SUPER_ADMIN_PASSWORD
  ) {
    return res.status(401).json({ success: false, message: 'Invalid super admin credentials' });
  }

  const token = jwt.sign(
    { role: 'superadmin', email },
    process.env.SUPER_ADMIN_JWT_SECRET,
    { expiresIn: '12h' }
  );

  res.json({ success: true, token });
});

// ─── GET ALL ACCOUNTS ───
// GET /api/superadmin/accounts
router.get('/accounts', superAdminProtect, async (req, res) => {
  try {
    const stores = await Store.find({})
      .populate('owner', 'name email isActive createdAt phone')
      .select('name slug category subscription isActive createdAt owner')
      .sort({ createdAt: -1 });

    const accounts = stores.map((store) => ({
      storeId: store._id,
      storeName: store.name,
      storeSlug: store.slug,
      category: store.category,
      storeActive: store.isActive,
      storeCreatedAt: store.createdAt,
      subscription: store.subscription,
      user: store.owner
        ? {
            userId: store.owner._id,
            name: store.owner.name,
            email: store.owner.email,
            phone: store.owner.phone,
            isActive: store.owner.isActive,
            registeredAt: store.owner.createdAt,
          }
        : null,
    }));

    res.json({ success: true, total: accounts.length, accounts });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── GET SINGLE ACCOUNT DETAIL ───
// GET /api/superadmin/accounts/:storeId
router.get('/accounts/:storeId', superAdminProtect, async (req, res) => {
  try {
    const store = await Store.findById(req.params.storeId)
      .populate('owner', 'name email isActive createdAt phone');
    if (!store) return res.status(404).json({ success: false, message: 'Store not found' });

    res.json({ success: true, store });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── CHANGE PLAN ───
// PUT /api/superadmin/accounts/:storeId/plan
router.put('/accounts/:storeId/plan', superAdminProtect, async (req, res) => {
  const { planId } = req.body;
  const plan = PLANS_CONFIG[planId];
  if (!plan) return res.status(400).json({ success: false, message: 'Invalid plan ID. Use: free, quarterly, halfyearly, yearly' });

  try {
    const newExpiry = new Date();
    newExpiry.setDate(newExpiry.getDate() + plan.durationDays);

    const store = await Store.findByIdAndUpdate(
      req.params.storeId,
      {
        'subscription.planId': planId,
        'subscription.planName': plan.name,
        'subscription.startDate': new Date(),
        'subscription.expiryDate': newExpiry,
        'subscription.status': 'active',
      },
      { new: true }
    );

    if (!store) return res.status(404).json({ success: false, message: 'Store not found' });

    res.json({ success: true, message: `Plan changed to ${plan.name}`, subscription: store.subscription });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── EXTEND EXPIRY DATE ───
// PUT /api/superadmin/accounts/:storeId/extend
router.put('/accounts/:storeId/extend', superAdminProtect, async (req, res) => {
  const { days, newExpiryDate } = req.body;

  try {
    const store = await Store.findById(req.params.storeId);
    if (!store) return res.status(404).json({ success: false, message: 'Store not found' });

    let updatedExpiry;

    if (newExpiryDate) {
      // Set exact date
      updatedExpiry = new Date(newExpiryDate);
    } else if (days) {
      // Extend from current expiry or now
      const base = store.subscription?.expiryDate
        ? new Date(store.subscription.expiryDate)
        : new Date();
      // If already expired, extend from now
      const fromDate = base < new Date() ? new Date() : base;
      fromDate.setDate(fromDate.getDate() + parseInt(days));
      updatedExpiry = fromDate;
    } else {
      return res.status(400).json({ success: false, message: 'Provide either days or newExpiryDate' });
    }

    store.subscription.expiryDate = updatedExpiry;
    store.subscription.status = 'active';
    await store.save();

    res.json({
      success: true,
      message: `Expiry extended to ${updatedExpiry.toDateString()}`,
      subscription: store.subscription,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── REVOKE / SUSPEND ACCOUNT ───
// PUT /api/superadmin/accounts/:storeId/revoke
router.put('/accounts/:storeId/revoke', superAdminProtect, async (req, res) => {
  const { action } = req.body; // 'suspend' or 'activate'

  try {
    const store = await Store.findById(req.params.storeId).populate('owner');
    if (!store) return res.status(404).json({ success: false, message: 'Store not found' });

    const isActive = action === 'activate';

    // Suspend/activate both store and user account
    await Store.findByIdAndUpdate(req.params.storeId, { isActive });
    await User.findByIdAndUpdate(store.owner._id, { isActive });

    if (action === 'suspend') {
      await Store.findByIdAndUpdate(req.params.storeId, {
        'subscription.status': 'canceled',
      });
    }

    res.json({
      success: true,
      message: `Account ${action === 'activate' ? 'activated' : 'suspended'} successfully`,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── CANCEL SUBSCRIPTION ───
// PUT /api/superadmin/accounts/:storeId/cancel-subscription
router.put('/accounts/:storeId/cancel-subscription', superAdminProtect, async (req, res) => {
  try {
    const store = await Store.findByIdAndUpdate(
      req.params.storeId,
      { 'subscription.status': 'canceled' },
      { new: true }
    );
    if (!store) return res.status(404).json({ success: false, message: 'Store not found' });

    res.json({ success: true, message: 'Subscription canceled', subscription: store.subscription });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ─── DASHBOARD STATS ───
// GET /api/superadmin/stats
router.get('/stats', superAdminProtect, async (req, res) => {
  try {
    const totalAccounts = await Store.countDocuments();
    const activeAccounts = await Store.countDocuments({ isActive: true });
    const suspendedAccounts = await Store.countDocuments({ isActive: false });

    const now = new Date();
    const activeSubscriptions = await Store.countDocuments({
      'subscription.status': 'active',
      'subscription.expiryDate': { $gt: now },
    });
    const expiredSubscriptions = await Store.countDocuments({
      $or: [
        { 'subscription.status': 'expired' },
        { 'subscription.expiryDate': { $lt: now } },
      ],
    });

    const planBreakdown = await Store.aggregate([
      { $group: { _id: '$subscription.planId', count: { $sum: 1 } } },
    ]);

    // New accounts in last 30 days
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const newAccountsThisMonth = await Store.countDocuments({
      createdAt: { $gte: thirtyDaysAgo },
    });

    res.json({
      success: true,
      stats: {
        totalAccounts,
        activeAccounts,
        suspendedAccounts,
        activeSubscriptions,
        expiredSubscriptions,
        newAccountsThisMonth,
        planBreakdown,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
