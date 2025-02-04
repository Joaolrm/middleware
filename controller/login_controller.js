const loginService = require('../service/login_service')
function realizarLogin(req, res) {
    const user = req.body;
    try {
        const token = loginService.verificarLogin(user);
        res.status(201).json(token);
    }
    catch (err) {
        res.status(err.id).json(err);
    }
}

module.exports = {
    realizarLogin
}