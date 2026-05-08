const express = require('express');
const router = express.Router();
const Service = require('../models/Service');
const Store = require('../models/Store');
const { protect } = require('../middleware/auth');
const upload = require('../middleware/upload');

// @GET /api/services/store/:storeId — Public: list services for a store
router.get('/store/:storeId', async (req, res) => {
  try {
    const query = { store: req.params.storeId, isActive: true };
    if (req.query.category) query.category = req.query.category;
    const services = await Service.find(query).sort('name');
    res.json({ success: true, services, count: services.length });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @GET /api/services/:id — Public: get single service
router.get('/:id', async (req, res) => {
  try {
    const service = await Service.findById(req.params.id).populate('store', 'name slug currency');
    if (!service || !service.isActive) {
      return res.status(404).json({ success: false, message: 'Service not found' });
    }
    res.json({ success: true, service });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @GET /api/services/:id/slots — Public: get available slots for a date
router.get('/:id/slots', async (req, res) => {
  try {
    const { date } = req.query;
    if (!date) return res.status(400).json({ success: false, message: 'Date is required' });

    const service = await Service.findById(req.params.id);
    if (!service) return res.status(404).json({ success: false, message: 'Service not found' });

    const Appointment = require('../models/Appointment');
    const dateObj = new Date(date);
    const dayName = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][dateObj.getDay()];

    // Check if blocked
    const isBlocked = service.blockedDates.some(
      d => new Date(d).toDateString() === dateObj.toDateString()
    );
    if (isBlocked) return res.json({ success: true, slots: [] });

    // Get availability for this day
    const dayAvail = service.availability.find(a => a.day === dayName);
    if (!dayAvail || !dayAvail.isAvailable) return res.json({ success: true, slots: [] });

    // Get already booked slots for this date
    const bookedAppointments = await Appointment.find({
      service: service._id,
      appointmentDate: {
        $gte: new Date(date),
        $lt: new Date(new Date(date).getTime() + 86400000)
      },
      status: { $in: ['pending', 'confirmed'] }
    }).select('startTime endTime');

    const bookedTimes = new Set(bookedAppointments.map(a => a.startTime));

    // Fetch external-calendar busy blocks (cached, 5-min TTL) — never blocks on failure
    const { getStoreBusyBlocks } = require('./calendar');
    const busyBlocks = await getStoreBusyBlocks(service.store, date).catch(() => []);

    const availableSlots = dayAvail.slots
      .filter(slot => {
        if (bookedTimes.has(slot.startTime)) return false;
        if (!busyBlocks.length) return true;
        const slotStart = new Date(`${date}T${slot.startTime}:00`);
        const slotEnd   = new Date(`${date}T${slot.endTime}:00`);
        return !busyBlocks.some(b => slotStart < new Date(b.end) && slotEnd > new Date(b.start));
      })
      .map(slot => ({ startTime: slot.startTime, endTime: slot.endTime }));

    res.json({ success: true, slots: availableSlots });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @GET /api/services/my/list — Provider: list own services
router.get('/my/list', protect, async (req, res) => {
  try {
    const store = await Store.findOne({ owner: req.user._id });
    if (!store) return res.status(404).json({ success: false, message: 'Store not found' });
    const services = await Service.find({ store: store._id }).sort('-createdAt');
    res.json({ success: true, services });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @POST /api/services — Provider: create service
router.post('/', protect, async (req, res) => {
  try {
    const store = await Store.findOne({ owner: req.user._id });
    if (!store) return res.status(404).json({ success: false, message: 'Store not found' });
    const service = await Service.create({ ...req.body, store: store._id });
    res.status(201).json({ success: true, service });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @PUT /api/services/:id — Provider: update service
router.put('/:id', protect, async (req, res) => {
  try {
    const store = await Store.findOne({ owner: req.user._id });
    const service = await Service.findOneAndUpdate(
      { _id: req.params.id, store: store._id },
      req.body,
      { new: true, runValidators: true }
    );
    if (!service) return res.status(404).json({ success: false, message: 'Service not found' });
    res.json({ success: true, service });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @DELETE /api/services/:id — Provider: delete service
router.delete('/:id', protect, async (req, res) => {
  try {
    const store = await Store.findOne({ owner: req.user._id });
    const service = await Service.findOneAndUpdate(
      { _id: req.params.id, store: store._id },
      { isActive: false },
      { new: true }
    );
    if (!service) return res.status(404).json({ success: false, message: 'Service not found' });
    res.json({ success: true, message: 'Service deleted' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// @POST /api/services/:id/images — Upload service images
router.post('/:id/images', protect, (req, res, next) => {
  req.uploadFolder = 'services';
  next();
}, upload.array('images', 5), async (req, res) => {
  try {
    const store = await Store.findOne({ owner: req.user._id });
    const imageUrls = req.files.map(f => `/uploads/services/${f.filename}`);
    const service = await Service.findOneAndUpdate(
      { _id: req.params.id, store: store._id },
      { $push: { images: { $each: imageUrls } } },
      { new: true }
    );
    res.json({ success: true, images: imageUrls, service });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;