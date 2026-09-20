module.exports = (req, res) => {
  res.status(200).json({ ok: true, service: "landhelpcenter-health", node: process.version, vercel: Boolean(process.env.VERCEL) });
};
