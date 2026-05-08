// middleware/checkSubscription.js
export const checkSubscription = (req, res, next) => {
  const { subscription } = req.store; // Assume store is attached to req
  
  if (new Date() > new Date(subscription.expiryDate)) {
    return res.status(403).json({ 
      message: "Subscription expired. Please upgrade to continue receiving bookings." 
    });
  }
  next();
};