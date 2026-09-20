try {
  module.exports = require('../server');
} catch (error) {
  module.exports = (req, res) => res.status(500).json({ ok:false, error: String(error && error.message || error), stack: String(error && error.stack || '').split('\\n').slice(0,8) });
}
