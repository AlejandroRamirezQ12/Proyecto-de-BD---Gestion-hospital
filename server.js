const express = require('express');
const app = express();
const path = require('path');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const session = require('express-session');
const bcrypt = require('bcrypt');
const multer = require('multer');
const xlsx = require('xlsx');
const fs = require('fs');
const PDFDocument = require('pdfkit');
require('dotenv').config();
 timezone: 'America/Tijuana'

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json()); // Procesar datos en formato JSON
app.use(express.urlencoded({ extended: true })); // Procesar datos tipo form-urlencoded

// Configuración de la sesión
app.use(session({
  secret: 'secretKey',
  resave: false,
  saveUninitialized: false,
}));

function requireRole(roles) {
  return (req, res, next) => {
    const userRole = req.session.user?.tipo_usuario; // Obtén el rol del usuario de la sesión
    if (!userRole) {
      return res.status(403).send('Acceso denegado');
    }

    if (Array.isArray(roles)) {
      // Verifica si el rol del usuario está en la lista permitida
      if (roles.includes(userRole)) {
        return next();
      }
    } else if (userRole === roles) {
      // Caso original: un solo rol permitido
      return next();
    }

    res.status(403).send('Acceso denegado');
  };
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login.html');
  }
  next();
}

// Ruta protegida (Página principal después de iniciar sesión)
app.get('/', requireLogin, (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});


// Servir archivos estáticos (HTML) ---------------- Configuración de Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Conexión a MySQL
const connection = mysql.createConnection({
  host: process.env.DB_HOST,       // Host desde .env
  user: process.env.DB_USER,       // Usuario desde .env
  password: process.env.DB_PASS,   // Contraseña desde .env
  database: process.env.DB_NAME    // Nombre de la base de datos desde .env 
});

connection.connect(err => {
  if (err) {
    console.error('Error conectando a MySQL:', err);
    return;
  }
  console.log('Conexión exitosa a MySQL');
});

connection.connect();


// Ruta para obtener el tipo de usuario actual
app.get('/tipo-usuario', requireLogin, (req, res) => {
  res.json({ tipo_usuario: req.session.user.tipo_usuario });
});

// Registro de usuario 
app.post('/registrar', (req, res) => {
  const { nombre_usuario, password, codigo_acceso } = req.body;

  const query = 'SELECT tipo_usuario FROM codigos_acceso WHERE codigo = ?';
  connection.query(query, [codigo_acceso], (err, results) => {
      if (err || results.length === 0) {
          return res.send('Código de acceso inválido');
      }

      const tipo_usuario = results[0].tipo_usuario.trim(); // Eliminamos espacios en blanco
      const hashedPassword = bcrypt.hashSync(password, 10);

      const insertUser = 'INSERT INTO usuarios (nombre_usuario, password_hash, tipo_usuario) VALUES (?, ?, ?)';
      connection.query(insertUser, [nombre_usuario, hashedPassword, tipo_usuario], (err) => {
          if (err) return res.send('Error al registrar usuario');

          // Redirigir según el tipo de usuario
          if (tipo_usuario === 'Gerente') {
              res.redirect('/login.html'); // Gerente no llena información adicional
          } else if (tipo_usuario === 'Doctor') {
              res.redirect(`/formulario-doctor.html?usuario=${encodeURIComponent(nombre_usuario)}`);
          } else if (tipo_usuario === 'Paciente') {
              res.redirect(`/formulario-paciente.html?usuario=${encodeURIComponent(nombre_usuario)}`);
          } else {
              res.send('Tipo de usuario no reconocido');
          }
      });
  });
});

// Ruta para registrar datos de pacientes
app.post('/registrar-paciente', (req, res) => {
  const { nombre, telefono, edad } = req.body; 

  const insertPaciente = 'INSERT INTO pacientes (nombre, telefono, edad) VALUES (?, ?, ?)';
  connection.query(insertPaciente, [nombre, telefono, edad], (err) => {
      if (err) {
          console.error('Error al registrar paciente:', err);
          return res.send('Error al registrar paciente');
      }
      console.log(`Paciente registrado correctamente: Nombre=${nombre}, Teléfono=${telefono}, Edad=${edad}`);
      res.redirect('/login.html');
  });
});

// Ruta para registrar datos de doctores
app.post('/registrar-doctor', (req, res) => {
  const { nombre, especialidad, horario_atencion, costo_consulta } = req.body; 

  const insertDoctor = 'INSERT INTO doctores (nombre, especialidad, horario_atencion, costo_consulta) VALUES (?, ?, ?, ?)';
  connection.query(insertDoctor, [nombre, especialidad, horario_atencion, costo_consulta], (err) => {
      if (err) {
          console.error('Error al registrar doctor:', err);
          return res.send('Error al registrar doctor');
      }
      console.log(`Doctor registrado correctamente: Nombre=${nombre}, Especialidad=${especialidad}, Horario=${horario_atencion}, Costo=${costo_consulta}`);
      res.redirect('/login.html');
  });
});

app.post('/login', (req, res) => {
  const { nombre_usuario, password } = req.body;


  // Consulta para obtener el usuario y su tipo
  const query = 'SELECT * FROM usuarios WHERE nombre_usuario = ?';
  connection.query(query, [nombre_usuario], async (err, results) => {
      if (err) {
          return res.send('Error al obtener el usuario');
      }


      if (results.length === 0) {
          return res.send('Usuario no encontrado');
      }


      const user = results[0];


      // Verificar la contraseña
      const isPasswordValid = bcrypt.compareSync(password, user.password_hash);
      if (!isPasswordValid) {
          return res.send('Contraseña incorrecta');
      }


      // Almacenar la información del usuario en la sesión
      req.session.user = {
          id: user.id,
          nombre_usuario: user.nombre_usuario,
          tipo_usuario: user.tipo_usuario // Aquí se establece el tipo de usuario en la sesión
      };
      // Redirigir al usuario a la página principal
      res.redirect('/');
  });
});

// Cerrar sesión
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});

// Ruta para mostrar los datos de la base de datos en formato HTML
app.get('/pacientes', requireLogin, requireRole('Doctor'), (req, res) => {
  connection.query('SELECT * FROM pacientes', (err, results) => {
    if (err) {
      return res.send('Error al obtener los datos.');
    }


    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Pacientes</title>
      </head>
      <body>
        <h1>Pacientes Registrados</h1>
        <table>
          <thead>
            <tr>
              <th>Nombre</th>
              <th>Edad</th>
              <th>Telefono</th>
            </tr>
          </thead>
          <tbody>
    `;


    results.forEach(paciente => {
      html += `
        <tr>
          <td>${paciente.nombre}</td>
          <td>${paciente.edad}</td>
          <td>${paciente.telefono}</td>
        </tr>
      `;
    });


    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/estadisticas-pacientes'">Estadisticas de la tabla de pacientes</button>
        <button onclick="window.location.href='/buscar-pacientes'">Buscar Paciente</button>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;


    res.send(html);
  });
});

// Ruta para mostrar la información de las citas utilizando la vista
app.get('/citas', requireLogin, requireRole('Doctor'), (req, res) => {
  const query = 'SELECT * FROM vista_citas';

  connection.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener los datos desde la vista:', err);
      return res.send('Error al obtener los datos.');
    }

    // Generar HTML con la información de las citas
    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Citas</title>
      </head>
      <body>
        <h1>Citas Registradas</h1>
        <table>
          <thead>
            <tr>
              <th>Fecha de la cita</th>
              <th>Motivo de la cita</th>
              <th>Paciente</th>
              <th>Doctor</th>
            </tr>
          </thead>
          <tbody>
    `;

    results.forEach(cita => {
      html += `
        <tr>
          <td>${cita.fecha_cita}</td>
          <td>${cita.motivo}</td>
          <td>${cita.paciente_nombre}</td>
          <td>${cita.doctor_nombre}</td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/buscar-citas'">Buscar Citas</button>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;

    res.send(html);
  });
});

// Ruta para mostrar la informacion de los tratamientos de la base de datos
app.get('/tratamientos', requireLogin, requireRole('Doctor'), (req, res) => {

  const query = `
    SELECT 
      tratamientos.descripcion, 
      tratamientos.costo, 
      tratamientos.fecha_inicio, 
      tratamientos.fecha_fin, 
      pacientes.nombre AS paciente_nombre
    FROM tratamientos
    JOIN pacientes ON tratamientos.paciente_id = pacientes.id
  `;

  connection.query(query, (err, results) => {
    if (err) {
      return res.send('Error al obtener los datos.');
    }

    // Generar HTML con la información de los tratamientos
    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Tratamientos</title>
      </head>
      <body>
        <h1>Tratamientos Registrados</h1>
        <table>
          <thead>
            <tr>
              <th>Descripción</th>
              <th>Costo</th>
              <th>Fecha de inicio</th>
              <th>Fecha de fin</th>
              <th>Paciente</th>
            </tr>
          </thead>
          <tbody>
    `;

    results.forEach(tratamiento => {
      html += `
        <tr>
          <td>${tratamiento.descripcion}</td>
          <td>${tratamiento.costo}</td>
          <td>${tratamiento.fecha_inicio}</td>
          <td>${tratamiento.fecha_fin}</td>
          <td>${tratamiento.paciente_nombre}</td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/buscar-tratamientos'">Buscar Tratamientos</button>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;

    res.send(html);
  });
});

// Ruta para buscar pacientes según filtros
app.get('/buscar-pacientes', requireLogin, requireRole('Doctor'), (req, res) => {
  const { name_search, age_search } = req.query;
  let query = 'SELECT * FROM pacientes WHERE 1=1';
  const params = [];

  if (name_search) {
    query += ' AND nombre LIKE ?';
    params.push(`%${name_search}%`);
  }
  if (age_search) {
    query += ' AND edad = ?';
    params.push(age_search);
  }

  connection.query(query, params, (err, results) => {
    if (err) {
      return res.send('Error al obtener los datos.');
    }

    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Buscar Pacientes</title>
      </head>
      <body>
        <h1>Buscar Pacientes</h1>
        <form method="GET" action="/buscar-pacientes">
          <label for="name_search">Nombre:</label>
          <input type="text" id="name_search" name="name_search" value="${name_search || ''}">
          <label for="age_search">Edad:</label>
          <input type="number" id="age_search" name="age_search" value="${age_search || ''}">
          <button type="submit">Buscar</button>
        </form>
        <h2>Resultados:</h2>
        <table>
          <thead>
            <tr>
              <th>Nombre</th>
              <th>Edad</th>
              <th>Teléfono</th>
            </tr>
          </thead>
          <tbody>
    `;

    results.forEach(paciente => {
      html += `
        <tr>
          <td>${paciente.nombre}</td>
          <td>${paciente.edad}</td>
          <td>${paciente.telefono}</td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/pacientes'">Volver</button>
      </body>
      </html>
    `;

    res.send(html);
  });
});

// Ruta para buscar citas según filtros
app.get('/buscar-citas', requireLogin, requireRole(['Paciente','Doctor']), (req, res) => {
  const { fecha_search, motivo_search, paciente_search, doctor_search } = req.query;
  
  let query = `
    SELECT 
      citas.fecha_cita, 
      citas.motivo, 
      pacientes.nombre AS paciente_nombre, 
      doctores.nombre AS doctor_nombre
    FROM citas
    JOIN pacientes ON citas.paciente_id = pacientes.id
    JOIN doctores ON citas.doctor_id = doctores.id
    WHERE 1=1
  `;
  const params = [];

  if (fecha_search) {
    query += ' AND citas.fecha_cita = ?';
    params.push(fecha_search);
  }
  if (motivo_search) {
    query += ' AND citas.motivo LIKE ?';
    params.push(`%${motivo_search}%`);
  }
  if (paciente_search) {
    query += ' AND pacientes.nombre LIKE ?';
    params.push(`%${paciente_search}%`);
  }
  if (doctor_search) {
    query += ' AND doctores.nombre LIKE ?';
    params.push(`%${doctor_search}%`);
  }

  connection.query(query, params, (err, results) => {
    if (err) {
      return res.send('Error al obtener los datos.');
    }

    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Buscar Citas</title>
      </head>
      <body>
        <h1>Buscar Citas</h1>
        <form method="GET" action="/buscar-citas">
          <label for="fecha_search">Fecha:</label>
          <input type="date" id="fecha_search" name="fecha_search" value="${fecha_search || ''}">
          <label for="motivo_search">Motivo:</label>
          <input type="text" id="motivo_search" name="motivo_search" value="${motivo_search || ''}">
          <label for="paciente_search">Paciente:</label>
          <input type="text" id="paciente_search" name="paciente_search" value="${paciente_search || ''}">
          <label for="doctor_search">Doctor:</label>
          <input type="text" id="doctor_search" name="doctor_search" value="${doctor_search || ''}">
          <button type="submit">Buscar</button>
        </form>
        <h2>Resultados:</h2>
        <table>
          <thead>
            <tr>
              <th>Fecha</th>
              <th>Motivo</th>
              <th>Paciente</th>
              <th>Doctor</th>
            </tr>
          </thead>
          <tbody>
    `;

    results.forEach(cita => {
      html += `
        <tr>
          <td>${cita.fecha_cita}</td>
          <td>${cita.motivo}</td>
          <td>${cita.paciente_nombre}</td>
          <td>${cita.doctor_nombre}</td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/citas'">Volver</button>
      </body>
      </html>
    `;

    res.send(html);
  });
});


// Ruta para buscar tratamientos según filtros
app.get('/buscar-tratamientos', requireLogin, requireRole(['Paciente','Doctor']), (req, res) => {
  const { descripcion_search, fecha_inicio_search, fecha_fin_search, paciente_search } = req.query;
  let query = `
    SELECT 
      tratamientos.descripcion, 
      tratamientos.costo, 
      tratamientos.fecha_inicio, 
      tratamientos.fecha_fin, 
      pacientes.nombre AS paciente_nombre
    FROM tratamientos
    JOIN pacientes ON tratamientos.paciente_id = pacientes.id
    WHERE 1=1
  `;
  const params = [];

  if (descripcion_search) {
    query += ' AND tratamientos.descripcion LIKE ?';
    params.push(`%${descripcion_search}%`);
  }
  if (fecha_inicio_search) {
    query += ' AND tratamientos.fecha_inicio >= ?';
    params.push(fecha_inicio_search);
  }
  if (fecha_fin_search) {
    query += ' AND tratamientos.fecha_fin <= ?';
    params.push(fecha_fin_search);
  }
  if (paciente_search) {
    query += ' AND pacientes.nombre LIKE ?';
    params.push(`%${paciente_search}%`);
  }

  connection.query(query, params, (err, results) => {
    if (err) {
      return res.send('Error al obtener los datos.');
    }

    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Buscar Tratamientos</title>
      </head>
      <body>
        <h1>Buscar Tratamientos</h1>
        <form method="GET" action="/buscar-tratamientos">
          <label for="descripcion_search">Descripción:</label>
          <input type="text" id="descripcion_search" name="descripcion_search" value="${descripcion_search || ''}">
          <label for="fecha_inicio_search">Fecha de inicio desde:</label>
          <input type="date" id="fecha_inicio_search" name="fecha_inicio_search" value="${fecha_inicio_search || ''}">
          <label for="fecha_fin_search">Fecha de fin hasta:</label>
          <input type="date" id="fecha_fin_search" name="fecha_fin_search" value="${fecha_fin_search || ''}">
          <label for="paciente_search">Paciente:</label>
          <input type="text" id="paciente_search" name="paciente_search" value="${paciente_search || ''}">
          <button type="submit">Buscar</button>
        </form>
        <h2>Resultados:</h2>
        <table>
          <thead>
            <tr>
              <th>Descripción</th>
              <th>Costo</th>
              <th>Fecha de inicio</th>
              <th>Fecha de fin</th>
              <th>Paciente</th>
            </tr>
          </thead>
          <tbody>
    `;

    results.forEach(tratamiento => {
      html += `
        <tr>
          <td>${tratamiento.descripcion}</td>
          <td>${tratamiento.costo}</td>
          <td>${tratamiento.fecha_inicio}</td>
          <td>${tratamiento.fecha_fin}</td>
          <td>${tratamiento.paciente_nombre}</td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/tratamientos'">Volver</button>
      </body>
      </html>
    `;

    res.send(html);
  });
});

// Ruta para obtener el promedio de edad y el total de pacientes
app.get('/estadisticas-pacientes', requireLogin, requireRole('Doctor'), (req, res) => {
  const query = `
    SELECT 
      (SELECT AVG(edad) FROM pacientes) AS promedio_edad,
      (SELECT COUNT(*) FROM pacientes) AS total_pacientes
  `;

  connection.query(query, (err, results) => {
    if (err) {
      return res.send('Error al obtener las estadísticas de los pacientes.');
    }

    // Extraer los resultados
    const { promedio_edad, total_pacientes } = results[0];

    // Generar HTML
    const html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Estadísticas de Pacientes</title>
      </head>
      <body>
        <h1>Estadísticas de los Pacientes</h1>
        <p>Promedio de edad: ${promedio_edad} años</p>
        <p>Total de pacientes registrados: ${total_pacientes}</p>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;

    res.send(html);
  });
});

// Ruta para que solo admin pueda ver todos los usuarios
app.get('/ver-usuarios', requireLogin, requireRole('Gerente'), (req, res) => {
  const query = 'SELECT * FROM usuarios';
  connection.query(query, (err, results) => {
      if (err) return res.send('Error al obtener usuarios');
      let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Usuarios</title>
      </head>
      <body>
        <h1>Usuarios Registrados</h1>
        <table>
          <thead>
            <tr>
              <th>Nombre</th>
              <th>Password_hash</th>
              <th>Tipo de usuario</th>
            </tr>
          </thead>
          <tbody>
    `;


    results.forEach(usuarios => {
      html += `
        <tr>
          <td>${usuarios.nombre_usuario}</td>
          <td>${usuarios.password_hash}</td>
          <td>${usuarios.tipo_usuario}</td>
        </tr>
      `;
    });


    html += `
          </tbody>
        </table>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;


    res.send(html);


  });
});

app.get('/ver-mis-datos', requireLogin, requireRole('Paciente'), (req, res) => {
  const userId = req.session.user.id; 

  const query = `
    SELECT usuarios.nombre_usuario, usuarios.tipo_usuario, usuarios.password_hash, pacientes.nombre, pacientes.edad, pacientes.telefono
    FROM usuarios
    JOIN pacientes ON usuarios.nombre_usuario = pacientes.nombre
    WHERE usuarios.id = ?;
  `;

  connection.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Error en la consulta SQL:", err);
      return res.status(500).send('Error al obtener los datos del paciente.');
    }

    if (results.length === 0) {
      return res.send('No se encontraron datos para este paciente.');
    }

    const paciente = results[0];

    let html = `
      <html>
      <head>
        <link rel="stylesheet" href="/styles.css">
        <title>Mis Datos</title>
      </head>
      <body>
        <h1>Mis Datos</h1>
        <table>
          <thead>
            <tr>
              <th>Campo</th>
              <th>Valor</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Nombre de Usuario</td>
              <td>${paciente.nombre_usuario}</td>
            </tr>
            <tr>
              <td>Tipo de Usuario</td>
              <td>${paciente.tipo_usuario}</td>
            </tr>
            <tr>
              <td>Password Hash</td>
              <td>${paciente.password_hash}</td>
            </tr>
            <tr>
              <td>Edad</td>
              <td>${paciente.edad}</td>
            </tr>
            <tr>
              <td>Telefono</td>
              <td>${paciente.telefono}</td>
            </tr>
          </tbody>
        </table>
        <button onclick="window.location.href='/'">Volver</button>
      </body>
      </html>
    `;

    res.send(html);
  });
});

app.get('/menu', (req, res) => {
  const menuItems = [
    { nombre: 'Informacion', url: '/InformacionRegistrada.html' },
    { nombre: 'Búsqueda', url: '/busqueda.html' }
  ];
  res.json(menuItems);
});

app.get('/buscar', (req, res) => {
  const query = req.query.query;
  const sql = `SELECT nombre_usuario, id FROM usuarios WHERE nombre_usuario LIKE ?`;
  connection.query(sql, [`%${query}%`], (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

const upload = multer({ dest: 'uploads/' });

app.post('/upload', upload.single('excelFile'), (req, res) => {
  const filePath = req.file.path;
  const workbook = xlsx.readFile(filePath);
  const sheetName = workbook.SheetNames[0];
  const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

  data.forEach(row => {
    const { nombre, edad, telefono } = row;
    const sql = `INSERT INTO pacientes (nombre, edad, telefono) VALUES (?, ?, ?)`;
    connection.query(sql, [nombre, edad, telefono], err => {
      if (err) throw err;
    });
  });

  res.send('<h1>Archivo cargado y datos guardados</h1><a href="/InformacionRegistrada.html">Volver</a>');
});

app.get('/download', (req, res) => {
  const sql = `SELECT * FROM pacientes`;
  connection.query(sql, (err, results) => {
    if (err) throw err;

    const worksheet = xlsx.utils.json_to_sheet(results);
    const workbook = xlsx.utils.book_new();
    xlsx.utils.book_append_sheet(workbook, worksheet, 'pacientes');

    const filePath = path.join(__dirname, 'uploads', 'pacientes.xlsx');
    xlsx.writeFile(workbook, filePath);
    res.download(filePath, 'pacientes.xlsx');
  });
});

/*
-----------------------------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------------------------
*/

// Ruta para obtener la lista de doctores
app.get('/doctores', (req, res) => {
  const query = 'SELECT id, nombre FROM doctores';
  connection.query(query, (err, results) => {
      if (err) {
          console.error('Error al obtener doctores:', err);
          return res.status(500).send('Error al obtener doctores');
      }
      res.json(results); // Enviar lista de doctores como JSON
  });
});

// Ruta para obtener la lista de pacientes
app.get('/pacientes1', (req, res) => {
  const query = 'SELECT id, nombre FROM pacientes';
  connection.query(query, (err, results) => {
      if (err) {
          console.error('Error al obtener pacientes:', err);
          return res.status(500).send('Error al obtener pacientes');
      }
      res.json(results); // Enviar lista de doctores como JSON
  });
});

// Ruta para registrar una cita
app.post('/registrar-cita', (req, res) => {
  const { paciente_id, doctor_id, fecha_cita, motivo } = req.body;

  // Iniciar la transacción
  connection.beginTransaction((err) => {
    if (err) {
      console.error('Error al iniciar transacción:', err);
      return res.status(500).send('Error al iniciar la transacción');
    }

    // Verificar que el paciente existe
    const checkPacienteQuery = 'SELECT id FROM pacientes WHERE id = ?';
    connection.query(checkPacienteQuery, [paciente_id], (err, results) => {
      if (err || results.length === 0) {
        return connection.rollback(() => {
          console.error('Paciente no encontrado:', err);
          res.status(404).send('Paciente no encontrado');
        });
      }

      // Insertar la cita en la tabla citas
      const insertCitaQuery = `
        INSERT INTO citas (fecha_cita, motivo, paciente_id, doctor_id)
        VALUES (?, ?, ?, ?)
      `;
      connection.query(insertCitaQuery, [fecha_cita, motivo, paciente_id, doctor_id], (err, results) => {
        if (err) {
          return connection.rollback(() => {
            console.error('Error al registrar cita:', err);
            res.status(500).send('Error al registrar la cita');
          });
        }

        // Confirmar la transacción
        connection.commit((err) => {
          if (err) {
            return connection.rollback(() => {
              console.error('Error al confirmar la transacción:', err);
              res.status(500).send('Error al confirmar la transacción');
            });
          }
          res.send('Cita registrada correctamente');
        });
      });
    });
  });
});

// Ruta para registrar un tratamiento
app.post('/registrar-tratamiento', (req, res) => {
  const { descripcion, costo, fecha_inicio, fecha_fin, paciente_id } = req.body;

  const query = `
      INSERT INTO tratamientos (descripcion, costo, fecha_inicio, fecha_fin, paciente_id)
      VALUES (?, ?, ?, ?, ?)
  `;
  connection.query(query, [descripcion, costo, fecha_inicio, fecha_fin, paciente_id], (err) => {
      if (err) {
          console.error('Error al registrar tratamiento:', err);
          return res.status(500).send('Error al registrar el tratamiento');
      }
      res.send('Tratamiento registrado correctamente');
  });
});

app.get('/downloadpdf-pacientes', requireLogin, requireRole('Gerente'), (req, res) => {
  const sql = 'SELECT id, nombre, apellido, telefono, TIMESTAMPDIFF(YEAR, fecha_nacimiento, CURDATE()) AS edad FROM pacientes';
  
  connection.query(sql, (err, results) => {
    if (err) {
      console.error("Error al consultar la base de datos:", err);
      return res.status(500).send('Error al obtener los datos.');
    }

    // Crear el documento PDF
    const doc = new PDFDocument({ autoFirstPage: false });
    const filePath = path.join(__dirname, 'uploads', 'pacientes.pdf');

    // Crear el archivo PDF en el sistema de archivos
    const stream = fs.createWriteStream(filePath);
    doc.pipe(stream);

    // Agregar una página al documento
    doc.addPage();

    // Título
    doc.fontSize(16).text('Reporte de Pacientes', { align: 'center' }).moveDown();

    // Subtítulo
    doc.fontSize(12).text('Información detallada de pacientes', { align: 'center' }).moveDown(2);

    // Cabecera de la tabla
    doc.fontSize(10).text('ID   Nombre Completo         Teléfono           Edad', { align: 'left' }).moveDown();

    // Agregar las filas de la tabla
    results.forEach((paciente) => {
      const nombreCompleto = `${paciente.nombre} ${paciente.apellido}`;
      doc.text(`${paciente.id}    ${nombreCompleto}    ${paciente.telefono}    ${paciente.edad}`, { align: 'left' }).moveDown();
    });

    // Finalizar el documento
    doc.end();

    // Cuando el archivo se haya generado, permitir la descarga
    stream.on('finish', () => {
      res.download(filePath, 'pacientes.pdf', (err) => {
        if (err) {
          console.error('Error al descargar el archivo:', err);
          res.status(500).send('Error al descargar el archivo.');
        } else {
          // Eliminar el archivo temporal después de la descarga
          fs.unlinkSync(filePath);
        }
      });
    });
  });
});

// Descargar archivo PDF
app.get('/download-pdf', (req, res) => {
  const sql = `SELECT id, nombre, edad, telefono FROM pacientes`;
  connection.query(sql, (err, results) => {
    if (err) throw err;

    const doc = new PDFDocument({ autoFirstPage: false });
    const filePath = path.join(__dirname, 'uploads', 'pacientes.pdf');
    const stream = fs.createWriteStream(filePath);
    doc.pipe(stream);

    doc.addPage();
    doc.fontSize(16).text('Reporte de Pacientes', { align: 'center' }).moveDown();
    doc.fontSize(12).text('Información registrada', { align: 'center' }).moveDown(2);
    doc.fontSize(10).text('ID   Nombre         Edad      Telefono', { align: 'left' }).moveDown();

    results.forEach(pacientes => {
      doc.text(`${pacientes.id}    ${pacientes.nombre}    ${pacientes.edad}    ${pacientes.telefono}`, { align: 'left' }).moveDown();
    });

    doc.end();

    stream.on('finish', () => {
      res.download(filePath, 'pacientes.pdf');
    });
  });
});

// Subir archivo PDF (simplemente guarda el archivo en el servidor)
app.post('/upload-pdf', upload.single('pdfFile'), (req, res) => {
  const filePath = req.file.path;
  const newFilePath = path.join(__dirname, 'uploads', req.file.originalname);

  // Renombrar el archivo para mantener su nombre original
  fs.renameSync(filePath, newFilePath);
  res.send('<h1>Archivo PDF cargado exitosamente</h1><a href="/InformacionRegistrada.html">Volver</a>');
});

// Ruta para insertar un paciente
app.post('/insertar-paciente', requireLogin, requireRole('Gerente'), (req, res) => {
  const { nombre, edad, telefono } = req.body;

  const query = 'INSERT INTO pacientes (nombre, edad, telefono) VALUES (?, ?, ?)';
  connection.query(query, [nombre, edad, telefono], err => {
    if (err) throw err;
    res.send('Paciente insertado correctamente.');
  });
});

// Ruta para insertar un doctor
app.post('/insertar-doctor', requireLogin, requireRole('Gerente'), (req, res) => {
  const { nombre, especialidad, costo_consulta, horario_atencion } = req.body;

  const query = 'INSERT INTO doctores (nombre, especialidad, costo_consulta, horario_atencion) VALUES (?, ?, ?, ?)';
  connection.query(query, [nombre, especialidad, costo_consulta, horario_atencion], err => {
    if (err) throw err;
    res.send('Doctor insertado correctamente.');
  });
});

// Ruta para modificar un paciente
app.post('/modificar-paciente', requireLogin, requireRole('Gerente'), (req, res) => {
  const { id, nombre, edad, telefono } = req.body;

  const query = 'UPDATE pacientes SET nombre = ?, edad = ?, telefono = ? WHERE id = ?';
  connection.query(query, [nombre, edad, telefono, id], err => {
    if (err) throw err;
    res.send('Paciente modificado correctamente.');
  });
});

// Ruta para modificar un doctor
app.post('/modificar-doctor', requireLogin, requireRole('Gerente'), (req, res) => {
  const { id, nombre, especialidad, costo_consulta, horario_atencion } = req.body;

  const query = 'UPDATE doctores SET nombre = ?, especialidad = ?, costo_consulta = ?, horario_atencion = ? WHERE id = ?';
  connection.query(query, [nombre, especialidad, costo_consulta, horario_atencion, id], err => {
    if (err) throw err;
    res.send('Doctor modificado correctamente.');
  });
});

// Ruta para eliminar un paciente
app.post('/eliminar-paciente', requireLogin, requireRole('Gerente'), (req, res) => {
  const { id } = req.body;

  const query = 'DELETE FROM pacientes WHERE id = ?';
  connection.query(query, [id], err => {
    if (err) throw err;
    res.send('Paciente eliminado correctamente.');
  });
});

// Ruta para eliminar un doctor
app.post('/eliminar-doctor', requireLogin, requireRole('Gerente'), (req, res) => {
  const { id } = req.body;

  const query = 'DELETE FROM doctores WHERE id = ?';
  connection.query(query, [id], err => {
    if (err) throw err;
    res.send('Doctor eliminado correctamente.');
  });
});

// Ruta para agregar columna a la tabla pacientes
app.post('/agregar-columna-pacientes', requireLogin, requireRole('Gerente'), (req, res) => {
  const { columna, tipo } = req.body; // columna es el nombre y tipo el tipo de dato, por ejemplo "VARCHAR(100)"

  const query = `ALTER TABLE pacientes ADD COLUMN ${columna} ${tipo}`;
  connection.query(query, err => {
    if (err) throw err;
    res.send(`Columna ${columna} agregada a la tabla pacientes.`);
  });
});

// Ruta para agregar columna a la tabla doctores
app.post('/agregar-columna-doctores', requireLogin, requireRole('Gerente'), (req, res) => {
  const { columna, tipo } = req.body; // columna es el nombre y tipo el tipo de dato

  const query = `ALTER TABLE doctores ADD COLUMN ${columna} ${tipo}`;
  connection.query(query, err => {
    if (err) throw err;
    res.send(`Columna ${columna} agregada a la tabla doctores.`);
  });
});

// Ruta para eliminar columna de la tabla pacientes
app.post('/eliminar-columna-pacientes', requireLogin, requireRole('Gerente'), (req, res) => {
  const { columna } = req.body; // columna es el nombre de la columna que se va a eliminar

  const query = `ALTER TABLE pacientes DROP COLUMN ${columna}`;
  connection.query(query, err => {
    if (err) throw err;
    res.send(`Columna ${columna} eliminada de la tabla pacientes.`);
  });
});

// Ruta para eliminar columna de la tabla doctores
app.post('/eliminar-columna-doctores', requireLogin, requireRole('Gerente'), (req, res) => {
  const { columna } = req.body;

  const query = `ALTER TABLE doctores DROP COLUMN ${columna}`;
  connection.query(query, err => {
    if (err) throw err;
    res.send(`Columna ${columna} eliminada de la tabla doctores.`);
  });
});

app.post('/eliminar-usuario', requireLogin, requireRole('Gerente'), (req, res) => {
  const userId = req.body.id;

  if (!userId) {
      return res.status(400).send('ID de usuario requerido');
  }

  const query = 'DELETE FROM usuarios WHERE id = ?';
  connection.query(query, [userId], (err, result) => {
      if (err) {
          console.error('Error al eliminar el usuario:', err);
          return res.status(500).send('Error al eliminar el usuario');
      }

      if (result.affectedRows === 0) {
          return res.status(404).send('Usuario no encontrado');
      }

      res.send('Usuario eliminado exitosamente');
  });
});

// Iniciar el servidor
app.listen(3000, () => {
  console.log('Servidor corriendo en http://localhost:3000');
});






