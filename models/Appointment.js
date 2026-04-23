const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');

const appointmentSchema = new mongoose.Schema({
  appointmentId: {
    type: String,
    default: () => uuidv4().substring(0, 8).toUpperCase(),
    unique: true
  },
  store: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Store',
    required: true
  },
  service: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Service',
    required: true
  },
  // Customer info (no account required)
  customer: {
    name: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String, required: true },
    notes: { type: String }
  },
  // Selected service options
  selectedOptions: [
    {
      label: String,
      value: String
    }
  ],
  // Appointment time
  appointmentDate: {
    type: Date,
    required: true
  },
  startTime: {
    type: String,
    required: true
  },
  endTime: {
    type: String,
    required: true
  },
  // Pricing
  originalPrice: {
    type: Number,
    required: true
  },
  discountAmount: {
    type: Number,
    default: 0
  },
  totalAmount: {
    type: Number,
    required: true
  },
  coupon: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Coupon',
    default: null
  },
  couponCode: {
    type: String,
    default: null
  },
  // Payment
  payment: {
    status: { type: String, enum: ['pending', 'paid', 'failed', 'refunded'], default: 'pending' },
    method: String,
    transactionId: String,
    paidAt: Date
  },
  // Status flow: pending → confirmed → completed / cancelled
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'completed', 'cancelled'],
    default: 'pending'
  },
  cancellationReason: {
    type: String,
    default: null
  },
  // Management token for customer to view/cancel without account
  managementToken: {
    type: String,
    default: () => uuidv4()
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

appointmentSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('Appointment', appointmentSchema);