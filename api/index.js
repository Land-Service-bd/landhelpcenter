module.exports = (req, res) => res.status(200).json({ ok: true, diagnostic: "api-index-loads", node: process.version, vercel: Boolean(process.env.VERCEL) });
