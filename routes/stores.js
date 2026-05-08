const express = require('express');
const router = express.Router();
const Store = require('../models/Store');
const { protect, authorize } = require('../middleware/auth');
const upload = require('../middleware/upload');

// @GET /api/stores/explore — Public: browse all active stores (mobile app discovery)
router.get('/explore/list', async (req, res) => {
  try {
    const { search, category, page = 1, limit = 20 } = req.query;
    const query = { isActive: true };
    if (category) query.category = category;
    if (search) query.$or = [
      { name: { $regex: search, $options: 'i' } },
      { description: { $regex: search, $options: 'i' } },
      { category: { $regex: search, $options: 'i' } },
    ];
    const Service = require('../models/Service');
    const Review = require('../models/Review');

    const stores = await Store.find(query)
      .select('name description slug logo banner category address phone isActive')
      .sort('-createdAt')
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    // Enrich with service count and avg rating
    const enriched = await Promise.all(stores.map(async (s) => {
      const [serviceCount, reviews] = await Promise.all([
        Service.countDocuments({ store: s._id, isActive: true }),
        Review.find({ store: s._id }).select('rating'),
      ]);
      const avgRating = reviews.length
        ? reviews.reduce((sum, r) => sum + r.rating, 0) / reviews.length
        : null;
      return { ...s.toObject(), serviceCount, avgRating: avgRating ? parseFloat(avgRating.toFixed(1)) : null, reviewCount: reviews.length };
    }));

    const total = await Store.countDocuments(query);
    res.json({ success: true, stores: enriched, total, page: parseInt(page), pages: Math.ceil(total / limit) });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @GET /api/stores/my/details — Provider: get own store
router.get('/my/details', protect, async (req, res) => {
  try {
    const store = await Store.findOne({ owner: req.user._id });
    if (!store) return res.status(404).json({ success: false, message: 'Store not found' });
    res.json({ success: true, store });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @PUT /api/stores/my — Provider: update own store
router.put('/my', protect, async (req, res) => {
  try {
    const allowedFields = [
      'name', 'description', 'category', 'address', 'phone',
      'email', 'website', 'socialLinks', 'businessHours', 'currency',
      'logo', 'banner', 'theme'
    ];
    const updates = {};
    allowedFields.forEach(f => { if (req.body[f] !== undefined) updates[f] = req.body[f]; });

    const store = await Store.findOneAndUpdate(
      { owner: req.user._id },
      updates,
      { new: true, runValidators: true }
    );
    res.json({ success: true, store });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @POST /api/stores/my/logo — Upload logo
router.post('/my/logo', protect, (req, res, next) => {
  req.uploadFolder = 'stores';
  next();
}, upload.single('logo'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, message: 'No file uploaded' });
    const logoUrl = `/uploads/stores/${req.file.filename}`;
    const store = await Store.findOneAndUpdate(
      { owner: req.user._id },
      { logo: logoUrl },
      { new: true }
    );
    res.json({ success: true, logo: logoUrl, store });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @POST /api/stores/my/banner — Upload banner
router.post('/my/banner', protect, (req, res, next) => {
  req.uploadFolder = 'stores';
  next();
}, upload.single('banner'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, message: 'No file uploaded' });
    const bannerUrl = `/uploads/stores/${req.file.filename}`;
    const store = await Store.findOneAndUpdate(
      { owner: req.user._id },
      { banner: bannerUrl },
      { new: true }
    );
    res.json({ success: true, banner: bannerUrl, store });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @PUT /api/stores/my/payment — Connect payment gateway
router.put('/my/payment', protect, async (req, res) => {
  try {
    const { provider, apiKey, secretKey } = req.body;
    const store = await Store.findOneAndUpdate(
      { owner: req.user._id },
      { paymentGateway: { provider, apiKey, secretKey, isConnected: true } },
      { new: true }
    );
    res.json({ success: true, message: 'Payment gateway connected', store });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @GET /api/stores/my/analytics — Provider analytics
router.get('/my/analytics', protect, async (req, res) => {
  try {
    const Appointment = require('../models/Appointment');
    const store = await Store.findOne({ owner: req.user._id });
    if (!store) return res.status(404).json({ success: false, message: 'Store not found' });

    const now = new Date();
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const startOfLastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1);
    const endOfLastMonth = new Date(now.getFullYear(), now.getMonth(), 0);

    const [total, thisMonth, lastMonth, revenue, statusBreakdown] = await Promise.all([
      Appointment.countDocuments({ store: store._id }),
      Appointment.countDocuments({ store: store._id, createdAt: { $gte: startOfMonth } }),
      Appointment.countDocuments({ store: store._id, createdAt: { $gte: startOfLastMonth, $lte: endOfLastMonth } }),
      Appointment.aggregate([
        { $match: { store: store._id, 'payment.status': 'paid' } },
        { $group: { _id: null, total: { $sum: '$totalAmount' } } }
      ]),
      Appointment.aggregate([
        { $match: { store: store._id } },
        { $group: { _id: '$status', count: { $sum: 1 } } }
      ])
    ]);

    res.json({
      success: true,
      analytics: {
        totalAppointments: total,
        thisMonthAppointments: thisMonth,
        lastMonthAppointments: lastMonth,
        totalRevenue: revenue[0]?.total || 0,
        statusBreakdown: statusBreakdown.reduce((acc, s) => { acc[s._id] = s.count; return acc; }, {})
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Enable / Disable payment
router.put('/my/payment/toggle', protect, async (req, res) => {
  const { enabled } = req.body;

  const store = await Store.findOneAndUpdate(
    { owner: req.user._id },
    { paymentEnabled: enabled },
    { new: true }
  );

  res.json({ success: true, store });
});

// ─── SUBSCRIPTION UPGRADE ───
const { upgradeStorePlan, getSubscription } = require('../controllers/subscriptionController');
router.get('/my/subscription', protect, getSubscription);
router.put('/my/upgrade', protect, upgradeStorePlan);

// Admin: list all stores
router.get('/', protect, authorize('admin'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const stores = await Store.find()
      .populate('owner', 'name email')
      .skip((page - 1) * limit)
      .limit(limit)
      .sort('-createdAt');
    const total = await Store.countDocuments();
    res.json({ success: true, stores, total, page, pages: Math.ceil(total / limit) });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @GET /api/stores/:slug  — Public: get store by slug (must be LAST — catch-all param route)
router.get('/:slug', async (req, res) => {
  try {
    const store = await Store.findOne({ slug: req.params.slug, isActive: true })
      .populate('owner', 'name email');
    if (!store) return res.status(404).json({ success: false, message: 'Store not found' });
    res.json({ success: true, store });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;