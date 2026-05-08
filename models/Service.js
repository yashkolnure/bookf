const mongoose = require('mongoose');

const serviceSchema = new mongoose.Schema({
  store: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Store',
    required: true
  },
  name: {
    type: String,
    required: [true, 'Service name is required'],
    trim: true,
    maxlength: [100, 'Service name cannot exceed 100 characters']
  },
  description: {
    type: String,
    maxlength: [1000, 'Description cannot exceed 1000 characters']
  },
  images: [{ type: String }],
  category: {
    type: String,
    trim: true
  },
  tags: [{ type: String, trim: true }],
  price: {
    type: Number,
    required: [true, 'Price is required'],
    min: [0, 'Price cannot be negative']
  },
  discountedPrice: {
    type: Number,
    min: [0, 'Discounted price cannot be negative'],
    default: null
  },
  duration: {
    type: Number, // in minutes
    required: [true, 'Duration is required'],
    min: [5, 'Duration must be at least 5 minutes']
  },
  options: [
    {
      label: String,
      values: [String]
    }
  ],
  // Availability slots - which days & times this service is available
  availability: [
    {
      day: { type: String, enum: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'] },
      isAvailable: { type: Boolean, default: true },
      slots: [
        {
          startTime: String, // "09:00"
          endTime: String    // "09:30"
        }
      ]
    }
  ],
  // Flexible pricing
  pricingType: {
    type: String,
    enum: ['fixed', 'per_hour', 'per_30min', 'per_15min'],
    default: 'fixed'
  },
  // Min/max session duration (minutes) — used when pricingType !== 'fixed'
  minDuration: {
    type: Number,
    default: null
  },
  maxDuration: {
    type: Number,
    default: null
  },
  // Blocked dates (holidays, etc.)
  blockedDates: [{ type: Date }],
  isActive: {
    type: Boolean,
    default: true
  },
  totalBookings: {
    type: Number,
    default: 0
  },
  rating: {
    average: { type: Number, default: 0 },
    count: { type: Number, default: 0 }
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Service', serviceSchema);