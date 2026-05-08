const express = require('express');
const router = express.Router();

const Appointment = require('../models/Appointment');
const Service = require('../models/Service');
const Store = require('../models/Store');
const Coupon = require('../models/Coupon');

const { protect } = require('../middleware/auth');
const crypto = require("crypto");


// ======================================================
// @POST /api/appointments
// Create appointment (after payment OR normal booking)
// ======================================================

// ── Flexible pricing helper ──────────────────────────────────────────────────
function calcServicePrice(service, durationMin) {
  const basePrice = service.discountedPrice || service.price;
  if (!service.pricingType || service.pricingType === 'fixed') return basePrice;
  const unitMap = { per_hour: 60, per_30min: 30, per_15min: 15 };
  const unit = unitMap[service.pricingType] || 60;
  const dur = Number(durationMin) || service.duration;
  return Math.round((basePrice / unit) * dur);
}

router.post('/', async (req, res) => {
  try {
    const {
      serviceId,
      storeId,
      appointmentDate,
      startTime,
      customer,
      selectedOptions,
      couponCode,
      payment,
      durationMinutes        // ← new: provided by frontend for time-based services
    } = req.body;

    // 🔍 Validate service
    const service = await Service.findById(serviceId);
    if (!service || !service.isActive) {
      return res.status(404).json({ success: false, message: 'Service not found' });
    }

    // 🚫 SLOT CHECK (only confirmed blocks)
    const existing = await Appointment.findOne({
      service: serviceId,
      appointmentDate: new Date(appointmentDate),
      startTime,
      status: { $in: ['confirmed'] }
    });

    if (existing) {
      return res.status(409).json({
        success: false,
        message: 'This time slot is already booked'
      });
    }

    // ⏰ Get endTime from availability
    const dayName = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][new Date(appointmentDate).getDay()];
    const dayAvail = service.availability.find(a => a.day === dayName);
    const slot = dayAvail?.slots.find(s => s.startTime === startTime);
    const endTime = slot?.endTime || startTime;

    // 💰 Pricing (supports fixed and time-based pricing)
    const originalPrice = calcServicePrice(service, durationMinutes);
    let discountAmount = 0;
    let appliedCoupon = null;

    if (couponCode) {
      const coupon = await Coupon.findOne({
        store: storeId,
        code: couponCode.toUpperCase(),
        isActive: true
      });

      if (coupon && (!coupon.expiresAt || coupon.expiresAt > new Date())) {
        if (!coupon.usageLimit || coupon.usedCount < coupon.usageLimit) {
          if (originalPrice >= coupon.minOrderAmount) {

            if (coupon.type === 'percentage') {
              discountAmount = (originalPrice * coupon.value) / 100;
              if (coupon.maxDiscount) {
                discountAmount = Math.min(discountAmount, coupon.maxDiscount);
              }
            } else {
              discountAmount = coupon.value;
            }

            appliedCoupon = coupon._id;
            coupon.usedCount += 1;
            await coupon.save();
          }
        }
      }
    }

    const totalAmount = Math.max(0, originalPrice - discountAmount);

    // 🔐 Generate unique token
    const managementToken = crypto.randomBytes(20).toString("hex");

    // 📌 Create appointment
    const appointment = await Appointment.create({
      store: storeId,
      service: serviceId,
      customer,
      selectedOptions,
      appointmentDate: new Date(appointmentDate),
      startTime,
      endTime,

      // 🔑 important
      managementToken,

      // ⏱️ actual session duration (time-based pricing)
      durationMinutes: durationMinutes || service.duration,

      // 💰 pricing
      originalPrice,
      discountAmount,
      totalAmount,
      coupon: appliedCoupon,
      couponCode: appliedCoupon ? couponCode.toUpperCase() : null,

      // ✅ STATUS LOGIC
      status: payment?.status === "paid" ? "confirmed" : "pending",

      // 💳 payment
      payment: payment || {}
    });

    // 📈 Increment bookings
    await Service.findByIdAndUpdate(serviceId, {
      $inc: { totalBookings: 1 }
    });

    // 📅 Push to provider's default calendar (fire-and-forget, non-blocking)
    try {
      const { createEventForAppointment } = require('./calendar');
      createEventForAppointment(storeId, appointment).catch(err =>
        console.error('Calendar push failed:', err.message)
      );
    } catch { /* calendar route not available — skip silently */ }

    res.status(201).json({
      success: true,
      appointment,
      managementLink: `/appointments/${appointment._id}?token=${appointment.managementToken}`
    });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


// ======================================================
// @GET /api/appointments/manage/:id
// Customer view appointment via token
// ======================================================

router.get('/manage/:id', async (req, res) => {
  try {
    const { token } = req.query;

    const appointment = await Appointment.findById(req.params.id)
      .populate('service', 'name images duration price pricingType minDuration maxDuration')
      .populate('store', 'name slug logo phone email');

    if (!appointment || appointment.managementToken !== token) {
      return res.status(403).json({
        success: false,
        message: 'Invalid or unauthorized'
      });
    }

    res.json({ success: true, appointment });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


// ======================================================
// @PUT /api/appointments/manage/:id/cancel
// Customer cancel appointment
// ======================================================

router.put('/manage/:id/cancel', async (req, res) => {
  try {
    const { token, reason } = req.body;

    const appointment = await Appointment.findById(req.params.id);

    if (!appointment || appointment.managementToken !== token) {
      return res.status(403).json({ success: false, message: 'Invalid or unauthorized' });
    }

    if (!['pending', 'confirmed'].includes(appointment.status)) {
      return res.status(400).json({ success: false, message: 'Cannot cancel this appointment' });
    }

    appointment.status = 'cancelled';
    appointment.cancellationReason = reason || 'Cancelled by customer';

    await appointment.save();

    res.json({ success: true, appointment });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


// ======================================================
// @POST /api/appointments/:id/payment
// OPTIONAL (can remove later)
// ======================================================

router.post('/:id/payment', async (req, res) => {
  try {
    const { transactionId, method } = req.body;

    const appointment = await Appointment.findByIdAndUpdate(
      req.params.id,
      {
        status: 'confirmed',
        'payment.status': 'paid',
        'payment.method': method || 'online',
        'payment.transactionId': transactionId || `TXN${Date.now()}`,
        'payment.paidAt': new Date()
      },
      { new: true }
    );

    res.json({ success: true, appointment });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


// ======================================================
// PROVIDER ROUTES
// ======================================================

// List appointments
router.get('/provider/list', protect, async (req, res) => {
  try {
    const store = await Store.findOne({ owner: req.user._id });

    const appointments = await Appointment.find({ store: store._id })
      .populate('service', 'name duration')
      .sort('-appointmentDate');

    res.json({ success: true, appointments });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


// Update status
router.put('/:id/status', protect, async (req, res) => {
  try {
    const store = await Store.findOne({ owner: req.user._id });
    const { status } = req.body;

    const appointment = await Appointment.findOne({
      _id: req.params.id,
      store: store._id
    });

    if (!appointment) {
      return res.status(404).json({ success: false, message: 'Not found' });
    }

    appointment.status = status;
    await appointment.save();

    res.json({ success: true, appointment });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


module.exports = router;