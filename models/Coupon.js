const mongoose = require('mongoose');

const couponSchema = new mongoose.Schema({
  store: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Store',
    required: true
  },
  code: {
    type: String,
    required: [true, 'Coupon code is required'],
    uppercase: true,
    trim: true
  },
  description: String,
  type: {
    type: String,
    enum: ['percentage', 'fixed'],
    required: true
  },
  value: {
    type: Number,
    required: [true, 'Discount value is required'],
    min: [0, 'Value cannot be negative']
  },
  minOrderAmount: {
    type: Number,
    default: 0
  },
  maxDiscount: {
    type: Number,
    default: null // max discount cap for percentage type
  },
  usageLimit: {
    type: Number,
    default: null // null = unlimited
  },
  usedCount: {
    type: Number,
    default: 0
  },
  applicableServices: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Service'
    }
  ], // empty = applies to all
  expiresAt: {
    type: Date,
    default: null
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Compound unique index: code per store
couponSchema.index({ store: 1, code: 1 }, { unique: true });

module.exports = mongoose.model('Coupon', couponSchema);