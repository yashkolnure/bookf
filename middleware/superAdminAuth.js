const jwt = require('jsonwebtoken');

const superAdminProtect = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Super admin access denied. No token.' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.SUPER_ADMIN_JWT_SECRET);
    if (decoded.role !== 'superadmin') {
      return res.status(403).json({ success: false, message: 'Not authorized as super admin' });
    }
    req.superAdmin = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Super admin token invalid or expired' });
  }
};

module.exports = { superAdminProtect };
