// middleware/riskCheck.js
// flags sessions with high risk

function flagHighRisk(req, res, next) {
    if (req.session && req.session.riskScore) {
        req.session.highRisk = req.session.riskScore > 60;
    }
    next();
}

module.exports = { flagHighRisk };
