const mongoose = require('mongoose');
const slugify = require('slugify');

const storeSchema = new mongoose.Schema({
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  name: {
    type: String,
    required: [true, 'Store name is required'],
    trim: true,
    maxlength: [80, 'Store name cannot exceed 80 characters']
  },
  slug: {
    type: String,
    unique: true
  },
  description: {
    type: String,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  logo: {
    type: String,
    default: null
  },
  banner: {
    type: String,
    default: null
  },
  category: {
    type: String,
    enum: ['salon', 'clinic', 'fitness', 'consulting', 'beauty', 'education', 'other'],
    default: 'other'
  },
  address: {
    street: String,
    city: String,
    state: String,
    country: String,
    zip: String
  },
  phone: String,
  email: String,
  website: String,
  socialLinks: {
    instagram: String,
    facebook: String,
    twitter: String
  },
  businessHours: [
    {
      day: { type: String, enum: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'] },
      isOpen: { type: Boolean, default: true },
      openTime: { type: String, default: '09:00' },
      closeTime: { type: String, default: '18:00' }
    }
  ],
  paymentGateway: {
    provider: { type: String, enum: ['stripe', 'razorpay', 'paypal', 'manual'], default: 'manual' },
    apiKey: { type: String, select: false },
    secretKey: { type: String, select: false },
    isConnected: { type: Boolean, default: false }
  },
  paymentEnabled: {
  type: Boolean,
  default: false
},
  currency: {
    type: String,
    default: 'INR'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  theme: {
    type: String,
    enum: ['classic', 'minimal', 'ocean', 'nature', 'sunset', 'rose', 'luxury'],
    default: 'classic'
  },
  rating: {
    average: { type: Number, default: 0 },
    count: { type: Number, default: 0 }
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  subscription: {
      planId: { type: String, default: 'free' }, // 'free', 'quarterly', 'halfyearly', 'yearly'
      planName: { type: String, default: '7 Day Free Trial' },
      startDate: { type: Date, default: Date.now },
      expiryDate: { 
        type: Date, 
        default: () => new Date(+new Date() + 7*24*60*60*1000) // 7 days from now
      },
      status: { type: String, enum: ['active', 'expired', 'canceled'], default: 'active' }
    }
});

// Auto-generate slug from store name
storeSchema.pre('save', async function (next) {
  if (!this.isModified('name')) return next();
  let baseSlug = slugify(this.name, { lower: true, strict: true });
  let slug = baseSlug;
  let counter = 1;
  while (await mongoose.model('Store').findOne({ slug, _id: { $ne: this._id } })) {
    slug = `${baseSlug}-${counter++}`;
  }
  this.slug = slug;
  next();
});

module.exports = mongoose.model('Store', storeSchema);