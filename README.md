Uso en un Componente React: Luego, en tu componente de login (por ejemplo, LoginPage.js), importarías y usarías esta función:

src/pages/LoginPage.js (ejemplo simplificado):
import React, { useState } from 'react';
import { login } from '../services/authService'; // Ajusta la ruta según tu estructura
import { useNavigate } from 'react-router-dom'; // Si usas React Router

function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate(); // Hook de React Router

  const handleSubmit = async (e) => {
    e.preventDefault();
    const result = await login(username, password);

    if (result.success) {
      alert(result.message);
      navigate('/admin/dashboard'); // Redirige a una ruta protegida
    } else {
      alert(result.message);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        placeholder="Usuario"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />
      <input
        type="password"
        placeholder="Contraseña"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <button type="submit">Iniciar Sesión</button>
    </form>
  );
}

export default LoginPage;
}

Lo que necesita ajustes / consideraciones para el futuro:

Base de Datos Real:
Instala un ORM/ODM: Para interactuar con tu base de datos (por ejemplo, Mongoose para MongoDB, Sequelize para SQL).
Recuperación de Usuarios en Login: En lugar de users.find(), harás una consulta a tu base de datos (ej. User.findOne({ username })).
Codigo:
// ... (imports)

// Antes de tu endpoint de login
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Nombre de usuario y contraseña son requeridos" });
  }

  // 1. Verificar si el usuario ya existe (en DB real)
  // const existingUser = await User.findOne({ username });
  // if (existingUser) {
  //   return res.status(409).json({ message: "El usuario ya existe" });
  // }

  try {
    // 2. Hashear la contraseña
    const hashedPassword = await bcrypt.hash(password, 10); // 10 es el número de rondas de sal

    // 3. Guardar el nuevo usuario en la DB (en DB real)
    // const newUser = new User({ username, password: hashedPassword });
    // await newUser.save();

    // Por ahora, solo simular el almacenamiento
    users.push({ username, password: hashedPassword }); // Agregando a tu fake DB

    res.status(201).json({ message: "Usuario registrado exitosamente" });
  } catch (error) {
    console.error("Error al registrar usuario:", error);
    res.status(500).json({ message: "Error interno del servidor al registrar" });
  }
});


Manejo de Errores Más Robusto:

En lugar de sendStatus(), es mejor enviar un JSON con un mensaje explicativo, como ya lo haces en el login. Esto ayuda al frontend a mostrar mensajes de error más útiles al usuario.

Implementa un middleware de manejo de errores global al final de tu server.js para capturar errores no manejados.

Ejemplo en authMiddleware:

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) { // Mejorar la verificación
    return res.status(401).json({ message: "No autorizado: Token no proporcionado o formato inválido" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // Ahora req.user.username estará disponible
    next();
  } catch (error) {
    console.error("Error al verificar token:", error);
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: "Token expirado" });
    }
    return res.status(403).json({ message: "Acceso denegado: Token inválido" });
  }
}

Redirección del Código
Para redirigir tu código hacia lo que estamos buscando (un sistema de autenticación robusto, listo para DB), te recomiendo los siguientes pasos:

Mantén tu server.js casi como está para el login. Solo agrega un nuevo endpoint para el registro de usuarios, donde ya implementes el hashing de la contraseña. Para la fase actual, puedes seguir usando tu "Fake DB" (users array) para probar ambos login y register. Asegúrate de que el hash de las contraseñas que agregues a tu array de users lo hagas con bcrypt.hash() antes de ponerlas ahí.

Crea el archivo src/services/authService.js en tu frontend (React) con la función login (y potencialmente logout y getToken).

Integra authService.js en tu componente de login en React. Haz las llamadas a la API y maneja la respuesta (guardar token, mostrar mensajes, redirigir).

Para las rutas protegidas en el frontend: Una vez que el usuario tiene un token, para acceder a /api/admin/data, tu frontend deberá enviar este token en el encabezado Authorization: Bearer <token>.

Ejemplo en el frontend para llamar a la ruta protegida:

import { getToken } from '../services/authService'; // Donde tengas tu función para obtener el token

async function getAdminData() {
  const token = getToken();
  if (!token) {
    alert("No estás logueado.");
    return;
  }

  try {
    const res = await fetch("http://localhost:3001/api/admin/data", {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}` // ¡Aquí se envía el token!
      },
    });

    if (res.ok) {
      const data = await res.json();
      alert(`Datos del admin: ${data.message}`);
    } else {
      const errorData = await res.json();
      alert(`Error al obtener datos del admin: ${errorData.message || res.statusText}`);
    }
  } catch (error) {
    console.error("Error al obtener datos del admin:", error);
    alert("No se pudo conectar con el servidor para obtener datos del admin.");
  }
}

// Luego, puedes llamar a esta función desde un botón o useEffect en tu componente de admin
// <button onClick={getAdminData}>Obtener Datos Secretos</button>
