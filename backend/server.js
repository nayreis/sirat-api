const express = require("express")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")

const app = express()

app.use(express.json())

// "banco de dados" temporário
const users = []

const authenticateToken = (req, res, next) => {

  const authHeader = req.headers["authorization"]

  const token = authHeader && authHeader.split(" ")[1]

  if (!token) {
    return res.status(401).json({
      message: "Token não fornecido"
    })
  }

  jwt.verify(token, "sirat-secret", (err, user) => {

    if (err) {
      return res.status(403).json({
        message: "Token inválido"
      })
    }

    req.user = user

    next()

  })

}

// rota inicial
app.get("/", (req, res) => {
  res.send("SIRAT API funcionando")
})


// cadastro de usuário
app.post("/register", async (req, res) => {

  const { name, email, password } = req.body

  const hashedPassword = await bcrypt.hash(password, 10)

  const user = {
    id: Date.now(),
    name,
    email,
    password: hashedPassword
  }

  users.push(user)

  res.json({
    message: "Usuário cadastrado com sucesso",
    user
  })

})


// login
app.post("/login", async (req, res) => {

  const { email, password } = req.body

  const user = users.find(u => u.email === email)

  if (!user) {
    return res.status(400).json({
      message: "Usuário não encontrado"
    })
  }

  const validPassword = await bcrypt.compare(password, user.password)

  if (!validPassword) {
    return res.status(400).json({
      message: "Senha inválida"
    })
  }

  const token = jwt.sign(
    { id: user.id },
    "sirat-secret",
    { expiresIn: "1h" }
  )

  res.json({
    message: "Login realizado com sucesso",
    token
  })

})

app.get("/tasks", authenticateToken, (req, res) => {

  res.json({
    message: "Acesso permitido",
    userId: req.user.id
  })

})

// iniciar servidor
app.listen(3888, () => {
  console.log("Servidor SIRAT rodando na porta 3888")
})