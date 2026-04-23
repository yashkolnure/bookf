const express = require('express');
const router = express.Router();
const Review = require('../models/Review');
const Appointment = require('../models/Appointment');
const { protect } = require('../middleware/auth');

// @GET /api/reviews/store/:storeId — Public: get store reviews
router.get('/store/:storeId', async (req, res) => {
  try {
    const reviews = await Review.find({ store: req.params.storeId, isApproved: true })
      .sort('-createdAt')
      .limit(50);
    res.json({ success: true, reviews });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @GET /api/reviews/service/:serviceId — Public: get service reviews
router.get('/service/:serviceId', async (req, res) => {
  try {
    const reviews = await Review.find({ service: req.params.serviceId, isApproved: true })
      .sort('-createdAt');
    res.json({ success: true, reviews });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @POST /api/reviews — Public: submit review (via management token)
router.post('/', async (req, res) => {
  try {
    const { appointmentId, token, rating, comment } = req.body;

    const appointment = await Appointment.findById(appointmentId)
      .populate('store')
      .populate('service');
    if (!appointment || appointment.managementToken !== token) {
      return res.status(403).json({ success: false, message: 'Invalid or unauthorized' });
    }
    if (appointment.status !== 'completed') {
      return res.status(400).json({ success: false, message: 'Can only review completed appointments' });
    }

    // Check duplicate
    const existing = await Review.findOne({ appointment: appointmentId });
    if (existing) {
      return res.status(400).json({ success: false, message: 'Review already submitted' });
    }

    const review = await Review.create({
      store: appointment.store._id,
      service: appointment.service._id,
      appointment: appointmentId,
      customer: {
        name: appointment.customer.name,
        email: appointment.customer.email
      },
      rating,
      comment
    });

    res.status(201).json({ success: true, review });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @GET /api/reviews/provider/list — Provider: see all reviews for their store
router.get('/provider/list', protect, async (req, res) => {
  try {
    const Store = require('../models/Store');
    const store = await Store.findOne({ owner: req.user._id });
    const reviews = await Review.find({ store: store._id })
      .populate('service', 'name')
      .sort('-createdAt');
    res.json({ success: true, reviews });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @DELETE /api/reviews/:id — Provider: delete a review
router.delete('/:id', protect, async (req, res) => {
  
  try {
    const Store = require('../models/Store');
    const store = await Store.findOne({ owner: req.user._id });
    const review = await Review.findOneAndDelete({ _id: req.params.id, store: store._id });
    if (!review) return res.status(404).json({ success: false, message: 'Review not found' });
    res.json({ success: true, message: 'Review deleted' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;