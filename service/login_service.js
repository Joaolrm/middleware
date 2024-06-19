const CHAVE_SECRETA = "Senac2024"
const jwt = require('jsonwebtoken')
const userAdmin = {
    id: 1,
    nome: "Admin",
    usuario: "admin",
    senha: "12345"
}

function verificarLogin(user) {
    if (user
        && user.usuario == userAdmin.usuario
        && user.senha == userAdmin.senha) {
        const token = jwt.sign({ id: userAdmin.id, nome: userAdmin.nome }, CHAVE_SECRETA, { expiresIn: '1h' })
        return token;
    };
    throw { id: 401, message: "Usuário ou senha invalidos" };
}

function verificaToken(token) {
    try {
        const payload = jwt.verify(token, CHAVE_SECRETA);
        if (payload) {
            return payload;
        }
        else {
            throw { id: 501, message: "Token invalido" };
        }
    }
    catch (err) {
        throw { id: 501, message: "Token invalido" };
    }
}

module.exports = {
    verificarLogin,
    verificaToken
}