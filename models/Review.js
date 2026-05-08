const mongoose = require('mongoose');

const reviewSchema = new mongoose.Schema({
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
  appointment: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Appointment',
    required: true,
    unique: true // one review per appointment
  },
  customer: {
    name: { type: String, required: true },
    email: { type: String, required: true }
  },
  rating: {
    type: Number,
    required: [true, 'Rating is required'],
    min: 1,
    max: 5
  },
  comment: {
    type: String,
    maxlength: [500, 'Review cannot exceed 500 characters']
  },
  isApproved: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Update store and service ratings after review save
reviewSchema.post('save', async function () {
  await updateRating('Store', this.store);
  await updateRating('Service', this.service);
});

async function updateRating(modelName, id) {
  const Review = mongoose.model('Review');
  const Model = mongoose.model(modelName);
  const stats = await Review.aggregate([
    { $match: { [modelName.toLowerCase()]: id, isApproved: true } },
    { $group: { _id: null, avgRating: { $avg: '$rating' }, count: { $sum: 1 } } }
  ]);
  if (stats.length > 0) {
    await Model.findByIdAndUpdate(id, {
      'rating.average': Math.round(stats[0].avgRating * 10) / 10,
      'rating.count': stats[0].count
    });
  }
}

module.exports = mongoose.model('Review', reviewSchema);