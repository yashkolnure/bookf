const Store = require('../models/Store');

const PLANS_CONFIG = {
  free: { name: '7 Day Free Trial', durationDays: 7 },
  quarterly: { name: 'Quarterly (3 Months)', durationDays: 90 },
  halfyearly: { name: 'Half Yearly (6 Months)', durationDays: 180 },
  yearly: { name: 'Yearly (1 Year)', durationDays: 365 },
};

const upgradeStorePlan = async (req, res) => {
  const { planId } = req.body;
  const plan = PLANS_CONFIG[planId];
  if (!plan) {
    return res.status(400).json({ success: false, message: 'Invalid plan. Choose: quarterly, halfyearly, yearly' });
  }
  try {
    const store = await Store.findOne({ owner: req.user._id });
    if (!store) return res.status(404).json({ success: false, message: 'Store not found' });
    const newExpiry = new Date();
    newExpiry.setDate(newExpiry.getDate() + plan.durationDays);
    const updatedStore = await Store.findByIdAndUpdate(
      store._id,
      { 'subscription.planId': planId, 'subscription.planName': plan.name,
        'subscription.startDate': new Date(), 'subscription.expiryDate': newExpiry,
        'subscription.status': 'active' },
      { new: true }
    );
    res.json({ success: true, message: 'Successfully upgraded to ' + plan.name, store: updatedStore });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Upgrade failed: ' + error.message });
  }
};

const getSubscription = async (req, res) => {
  try {
    const store = await Store.findOne({ owner: req.user._id }).select('subscription name');
    if (!store) return res.status(404).json({ success: false, message: 'Store not found' });
    res.json({ success: true, subscription: store.subscription });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

module.exports = { upgradeStorePlan, getSubscription };
