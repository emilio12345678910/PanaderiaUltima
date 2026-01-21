const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');

const PORT = process.env.PORT || 3000;
const app = express();

// Configuración de body parser
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Configuración para confiar en el proxy de Render en producción
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

// Sesiones (configuración para desarrollo y producción)
app.use(session({
  secret: process.env.SESSION_SECRET || 'cambiame_en_produccion',
  resave: true,
  saveUninitialized: true,
  cookie: { 
    maxAge: 1000 * 60 * 60 * 24, // 24 horas
    // En producción, secure será true solo si estamos usando HTTPS
    secure: false,
    sameSite: 'lax'
  },
  name: 'sessionId', // Nombre personalizado para la cookie
  rolling: true // Renueva el tiempo de expiración en cada petición
}));

// Servir contenido estático (frontend)
app.use(express.static(path.join(__dirname, 'public')));

// Configuración de base de datos MySQL
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'sql5.freesqldatabase.com',
  user: process.env.DB_USER || 'sql5814847',
  password: process.env.DB_PASSWORD || 'bnpp3csArx',
  database: process.env.DB_NAME || 'sql5814847',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Agregar fondos al perfil del usuario (limite máximo)
app.post('/api/usuarios/fondos', requireAuth, (req, res) => {
  const cantidad = Number(req.body.cantidad);
  if (isNaN(cantidad) || cantidad <= 0) return res.status(400).json({ error: 'Cantidad inválida' });
  if (cantidad > MAX_FONDOS) return res.status(400).json({ error: 'Cantidad excede el límite permitido' });

  const idUsuario = req.session.usuario.id;
  pool.query('SELECT fondos FROM usuarios WHERE id = ?', [idUsuario], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Error del servidor' });
    if (rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    const actuales = Number(rows[0].fondos || 0);
    const nuevo = actuales + cantidad;
    if (nuevo > MAX_FONDOS) return res.status(400).json({ error: 'Supera el máximo permitido' });
    pool.query('UPDATE usuarios SET fondos = ? WHERE id = ?', [nuevo, idUsuario], (errUpd) => {
      if (errUpd) return res.status(500).json({ error: 'Error actualizando fondos' });
      res.json({ ok: true, fondos: nuevo });
    });
  });
});

// Rutas CRUD de usuarios (solo admin)
app.get('/api/usuarios', requireAuth, requireRole('admin'), (req, res) => {
  pool.query('SELECT id, usuario, email, rol, fondos FROM usuarios', (err, filas) => {
    if (err) return res.status(500).json({ error: 'Error obteniendo usuarios' });
    res.json(filas);
  });
});

app.get('/api/usuarios/:id', requireAuth, requireRole('admin'), (req, res) => {
  const id = req.params.id;
  pool.query('SELECT id, usuario, email, rol, fondos FROM usuarios WHERE id = ?', [id], (err, filas) => {
    if (err) return res.status(500).json({ error: 'Error obteniendo usuario' });
    if (filas.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json(filas[0]);
  });
});

app.put('/api/usuarios/:id', requireAuth, requireRole('admin'), (req, res) => {
  const id = req.params.id;
  const { email, rol, contrasena } = req.body;
  const updates = [];
  const params = [];
  if (email) { updates.push('email = ?'); params.push(email); }
  if (rol) { updates.push('rol = ?'); params.push(rol); }
  if (contrasena) { const hash = bcrypt.hashSync(contrasena, 10); updates.push('contrasena = ?'); params.push(hash); }
  if (updates.length === 0) return res.status(400).json({ error: 'Nada para actualizar' });
  params.push(id);
  const sql = 'UPDATE usuarios SET ' + updates.join(', ') + ' WHERE id = ?';
  pool.query(sql, params, (err, result) => {
    if (err) return res.status(500).json({ error: 'Error actualizando usuario' });
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json({ ok: true });
  });
});

app.delete('/api/usuarios/:id', requireAuth, requireRole('admin'), (req, res) => {
  const id = req.params.id;
  pool.query('DELETE FROM usuarios WHERE id = ?', [id], (err, result) => {
    if (err) return res.status(500).json({ error: 'Error borrando usuario' });
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json({ ok: true });
  });
});

// Admin: establecer fondos de un usuario (valor absoluto, con validación)
app.put('/api/usuarios/:id/fondos', requireAuth, requireRole('admin'), (req, res) => {
  const id = req.params.id;
  const fondos = Number(req.body.fondos);
  if (isNaN(fondos) || fondos < 0) return res.status(400).json({ error: 'Fondos inválidos' });
  if (fondos > MAX_FONDOS) return res.status(400).json({ error: 'Fondos exceden el máximo permitido' });

  pool.query('UPDATE usuarios SET fondos = ? WHERE id = ?', [fondos, id], (err, result) => {
    if (err) {
      console.error('Error actualizando fondos (admin):', err);
      return res.status(500).json({ error: 'Error actualizando fondos' });
    }
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json({ ok: true, id: id, fondos: fondos });
  });
});

// Registro de nuevo usuario
app.post('/api/registro', (req, res) => {
  const { usuario, contrasena, email } = req.body;
  if (!usuario || !contrasena || !email) return res.status(400).json({ error: 'usuario, contrasena y email son requeridos' });
  if (usuario.length < 3 || contrasena.length < 6) return res.status(400).json({ error: 'Usuario o contraseña demasiado cortos' });

  // validar email gmail obligatorio
  if (!/^[^@\s]+@gmail\.com$/i.test(email)) return res.status(400).json({ error: 'Solo se permiten correos @gmail.com para el registro' });

  pool.query('SELECT id FROM usuarios WHERE usuario = ? OR email = ?', [usuario, email], (err, rows) => {
    if (err) {
      console.error('Error verificando usuario existente:', err);
      return res.status(500).json({ error: 'Error del servidor' });
    }
    if (rows.length > 0) return res.status(400).json({ error: 'Usuario o email ya registrado' });

    const hash = bcrypt.hashSync(contrasena, 10);
    // solo crear usuarios normales (user). No permitir crear admins desde registro.
    pool.query('INSERT INTO usuarios (usuario, contrasena, email, rol, fondos) VALUES (?, ?, ?, ?, ?)',
      [usuario, hash, email, 'user', 0], (errIns) => {
        if (errIns) {
          console.error('Error registrando usuario:', errIns);
          return res.status(500).json({ error: 'Error al registrar usuario' });
        }
        res.json({ ok: true });
      });
  });
});
const VALID_TEMPORADAS = ['normal', 'navideño'];
const MAX_FONDOS = 999999999999;

// Re-hashear contraseñas en texto plano (si existen) al iniciar la app.
function rehashPlainPasswords() {
  pool.query('SELECT id, contrasena FROM usuarios', (err, rows) => {
    if (err) return console.error('Error comprobando contraseñas:', err);
    rows.forEach(u => {
      const pass = u.contrasena || '';
      if (!/^\$2[aby]\$/.test(pass)) {
        try {
          const hashed = bcrypt.hashSync(pass, 10);
          pool.query('UPDATE usuarios SET contrasena = ? WHERE id = ?', [hashed, u.id], (err) => {
            if (err) console.error('Error actualizando hash de usuario', u.id, err);
            else console.log('Hasheada contraseña de usuario id=', u.id);
          });
        } catch (e) {
          console.error('Error al hashear contraseña:', e);
        }
      }
    });
  });
}

// Ejecutar rehash en arranque (intento silencioso)
rehashPlainPasswords();

// Helper: middleware para asegurar sesión / roles
function requireAuth(req, res, next) {
  // Verificación más completa de la sesión
  if (req.session && req.session.autenticado && req.session.usuario) {
    // Renovar la cookie en cada petición
    req.session.touch();
    return next();
  }
  return res.status(401).json({ error: 'No autorizado' });
}

function requireRole(rol) {
  return (req, res, next) => {
    if (req.session && req.session.usuario) {
      // Si el rol no está definido y el usuario es 'admin', asumimos que tiene todos los permisos
      if (!req.session.usuario.rol && req.session.usuario.usuario === 'admin') {
        return next();
      }
      // Si el rol coincide, permitimos el acceso
      if (req.session.usuario.rol === rol) {
        return next();
      }
    }
    return res.status(403).json({ error: 'Permiso denegado' });
  };
}

// --- Rutas de autenticación ---
app.post('/api/iniciar-sesion', (req, res) => {
  const { usuario, contrasena } = req.body;
  if (!usuario || !contrasena) return res.status(400).json({ error: 'Usuario y contraseña son requeridos' });

  pool.query('SELECT id, usuario, contrasena, rol FROM usuarios WHERE usuario = ?', [usuario], (err, rows) => {
    if (err) {
      console.error('Error en BD al iniciar sesión:', err);
      return res.status(500).json({ error: 'Error del servidor' });
    }
    if (rows.length === 0) return res.status(400).json({ error: 'Credenciales inválidas' });
    const datosUsuario = rows[0];
      // Comparar con bcrypt
      try {
        const ok = bcrypt.compareSync(contrasena, datosUsuario.contrasena || '');
        if (!ok) return res.status(400).json({ error: 'Credenciales inválidas' });
      } catch (e) {
        console.error('Error comparando contraseñas:', e);
        return res.status(500).json({ error: 'Error del servidor' });
      }

    // Preparar los datos del usuario
    const datosParaSesion = {
      id: datosUsuario.id,
      usuario: datosUsuario.usuario,
      rol: datosUsuario.rol || (datosUsuario.usuario === 'admin' ? 'admin' : 'user')
    };

    // Guardar en sesión
    req.session.usuario = datosParaSesion;
    req.session.autenticado = true; // Flag explícito de autenticación

    // Forzar la regeneración del ID de sesión cuando iniciamos sesión
    req.session.regenerate((err) => {
      if (err) {
        console.error('Error al regenerar la sesión:', err);
        return res.status(500).json({ error: 'Error al iniciar sesión' });
      }

      // Volver a establecer los datos del usuario en la nueva sesión
      req.session.usuario = datosParaSesion;
      req.session.autenticado = true;

      // Guardar la sesión
      req.session.save((err) => {
        if (err) {
          console.error('Error al guardar la sesión:', err);
          return res.status(500).json({ error: 'Error al guardar la sesión' });
        }

        // Responder con los datos necesarios
        return res.json({
          ok: true,
          rol: datosParaSesion.rol,
          usuario: datosParaSesion
        });
      });
    });
  });
});

app.post('/api/cerrar-sesion', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Error destruyendo sesión:', err);
      return res.status(500).json({ error: 'No se pudo cerrar sesión' });
    }
    res.json({ ok: true });
  });
});

app.get('/api/usuario', (req, res) => {
  console.log('Verificando sesión:', {
    tieneSession: !!req.session,
    autenticado: req.session?.autenticado,
    usuario: req.session?.usuario
  });

  if (req.session && req.session.autenticado && req.session.usuario) {
    // Renovar la cookie en cada verificación exitosa
    req.session.touch();
    // Además de los datos de sesión, intentar traer fondos y email desde la BD
    const idUsuario = req.session.usuario.id;
    pool.query('SELECT id, usuario, email, rol, fondos FROM usuarios WHERE id = ?', [idUsuario], (err, filas) => {
      if (err) {
        console.error('Error obteniendo datos de usuario en /api/usuario:', err);
        return res.json({ usuario: req.session.usuario, autenticado: true });
      }
      if (filas && filas.length) {
        const fila = filas[0];
        // actualizar la sesión con rol si es necesario
        req.session.usuario = req.session.usuario || {};
        req.session.usuario.rol = fila.rol || req.session.usuario.rol;
        return res.json({ usuario: { id: fila.id, usuario: fila.usuario, email: fila.email, rol: fila.rol, fondos: Number(fila.fondos || 0) }, autenticado: true });
      }
      return res.json({ usuario: req.session.usuario, autenticado: true });
    });
    return;
  }
  return res.status(401).json({ 
    error: 'No autenticado',
    autenticado: false
  });
});

// --- Productos (CRUD) ---
app.get('/api/productos', (req, res) => {
  pool.query('SELECT id, nombre, url_imagen, precio, cantidad, temporada FROM productos', (err, rows) => {
    if (err) {
      console.error('Error obteniendo productos:', err);
      return res.status(500).json({ error: 'Error al obtener productos' });
    }
    res.json(rows);
  });
});

app.post('/api/productos', requireAuth, requireRole('admin'), (req, res) => {
  const { nombre, url_imagen, precio, cantidad, temporada } = req.body;
  if (!nombre || !url_imagen || precio == null || cantidad == null || !temporada) {
    return res.status(400).json({ error: 'Campos requeridos: nombre, url_imagen, precio, cantidad, temporada' });
  }
  // Validaciones adicionales
  if (typeof nombre !== 'string' || nombre.trim().length < 1) return res.status(400).json({ error: 'Nombre inválido' });
  if (!VALID_TEMPORADAS.includes(temporada)) return res.status(400).json({ error: 'Temporada inválida' });
  const p = Number(precio);
  const q = Number(cantidad);
  if (isNaN(p) || p <= 0 || p > 10000000) return res.status(400).json({ error: 'Precio inválido' });
  if (!Number.isInteger(q) || q < 0 || q > 1000000000) return res.status(400).json({ error: 'Cantidad inválida' });
  pool.query('INSERT INTO productos (nombre, url_imagen, precio, cantidad, temporada) VALUES (?, ?, ?, ?, ?)',
    [nombre, url_imagen, precio, cantidad, temporada], (err, result) => {
      if (err) {
        console.error('Error insert product:', err);
        return res.status(500).json({ error: 'Error al crear producto' });
      }
      res.json({ ok: true, id: result.insertId });
    });
});

app.put('/api/productos/:id', requireAuth, requireRole('admin'), (req, res) => {
  const id = req.params.id;
  const { nombre, url_imagen, precio, cantidad, temporada } = req.body;
  if (!nombre || !url_imagen || precio == null || cantidad == null || !temporada) {
    return res.status(400).json({ error: 'Campos requeridos: nombre, url_imagen, precio, cantidad, temporada' });
  }
  if (!VALID_TEMPORADAS.includes(temporada)) return res.status(400).json({ error: 'Temporada inválida' });
  const p = Number(precio);
  const q = Number(cantidad);
  if (isNaN(p) || p <= 0 || p > 10000000) return res.status(400).json({ error: 'Precio inválido' });
  if (!Number.isInteger(q) || q < 0 || q > 1000000000) return res.status(400).json({ error: 'Cantidad inválida' });
  pool.query('UPDATE productos SET nombre=?, url_imagen=?, precio=?, cantidad=?, temporada=? WHERE id=?',
    [nombre, url_imagen, precio, cantidad, temporada, id], (err, result) => {
      if (err) {
        console.error('Error actualizando producto:', err);
        return res.status(500).json({ error: 'Error al actualizar producto' });
      }
      if (result.affectedRows === 0) return res.status(404).json({ error: 'Producto no encontrado' });
      res.json({ ok: true });
    });
});

app.delete('/api/productos/:id', requireAuth, requireRole('admin'), (req, res) => {
  const id = req.params.id;
  pool.query('DELETE FROM productos WHERE id = ?', [id], (err, result) => {
    if (err) {
      console.error('Error borrando producto:', err);
      return res.status(500).json({ error: 'Error al borrar producto' });
    }
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Producto no encontrado' });
    res.json({ ok: true });
  });
});

// --- Carrito ---
// Añadir al carrito por sesión
app.post('/api/carrito/agregar', (req, res) => {
  const idSesion = req.session.id;
  const { id_producto, cantidad } = req.body;
  if (!id_producto || !cantidad || cantidad <= 0) {
    return res.status(400).json({ error: 'id_producto y cantidad válidos son requeridos' });
  }

  // Solo verificar que haya suficiente stock, pero no reservarlo aún
  pool.query('SELECT cantidad FROM productos WHERE id = ?', [id_producto], (err, rows) => {
    if (err) {
      console.error('Error comprobando stock:', err);
      return res.status(500).json({ error: 'Error del servidor' });
    }
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Producto no encontrado' });
    }

    const disponible = rows[0].cantidad;
    if (cantidad > disponible) {
      return res.status(400).json({ error: 'Cantidad solicitada mayor al stock disponible' });
    }

    // Comprobar si ya hay fila en carrito
    pool.query('SELECT id, cantidad FROM carrito WHERE sesion_id = ? AND producto_id = ?', 
      [idSesion, id_producto], (errCar, filasCarrito) => {
        if (errCar) {
          console.error('Error en carrito:', errCar);
          return res.status(500).json({ error: 'Error del servidor' });
        }

        const cantidadAAgregar = Number(cantidad);

        if (filasCarrito.length === 0) {
          // Insertar nuevo item en carrito
          pool.query('INSERT INTO carrito (sesion_id, producto_id, cantidad) VALUES (?, ?, ?)',
            [idSesion, id_producto, cantidadAAgregar], (errIns) => {
              if (errIns) {
                console.error('Error al insertar en carrito:', errIns);
                return res.status(500).json({ error: 'Error al agregar al carrito' });
              }
              res.json({ ok: true });
            });
        } else {
          // Actualizar cantidad existente en carrito
          const nuevaCantidad = Number(filasCarrito[0].cantidad) + cantidadAAgregar;
          // Validar que la cantidad total no supere el stock
          if (nuevaCantidad > disponible) {
            return res.status(400).json({ error: 'La cantidad total en el carrito superaría el stock disponible' });
          }
          pool.query('UPDATE carrito SET cantidad = ? WHERE id = ?',
            [nuevaCantidad, filasCarrito[0].id], (errUpdCar) => {
              if (errUpdCar) {
                console.error('Error al actualizar carrito:', errUpdCar);
                return res.status(500).json({ error: 'Error al actualizar carrito' });
              }
              res.json({ ok: true });
            });
        }
    });
  });
});

app.get('/api/carrito', (req, res) => {
  const idSesion = req.session.id;
  pool.query('SELECT c.producto_id, c.cantidad, p.nombre, p.url_imagen, p.precio FROM carrito c JOIN productos p ON c.producto_id = p.id WHERE c.sesion_id = ?', [idSesion], (err, rows) => {
    if (err) {
      console.error('Error obteniendo carrito:', err);
      return res.status(500).json({ error: 'Error al obtener carrito' });
    }
    res.json(rows);
  });
});

// Eliminar item del carrito
app.post('/api/carrito/eliminar', (req, res) => {
  const idSesion = req.session.id;
  const { id_producto } = req.body;
  
  if (!id_producto) {
    return res.status(400).json({ error: 'ID de producto requerido' });
  }

  // Primero, obtener la cantidad actual para restaurarla al producto
  pool.query('SELECT cantidad FROM carrito WHERE sesion_id = ? AND producto_id = ?', 
    [idSesion, id_producto], (err, rows) => {
      if (err) {
        console.error('Error consultando carrito:', err);
        return res.status(500).json({ error: 'Error al eliminar del carrito' });
      }
      
      if (rows.length === 0) {
        return res.status(404).json({ error: 'Producto no encontrado en el carrito' });
      }
      
      const cantidadARestaurar = rows[0].cantidad;

      // Eliminar del carrito y restaurar cantidad al producto
      pool.getConnection((err, conn) => {
        if (err) {
          console.error('Error obteniendo conexión:', err);
          return res.status(500).json({ error: 'Error del servidor' });
        }

        conn.beginTransaction(err => {
          if (err) {
            conn.release();
            return res.status(500).json({ error: 'Error del servidor' });
          }

          // Eliminar del carrito
          conn.query('DELETE FROM carrito WHERE sesion_id = ? AND producto_id = ?',
            [idSesion, id_producto], (err) => {
              if (err) {
                return conn.rollback(() => {
                  conn.release();
                  res.status(500).json({ error: 'Error al eliminar del carrito' });
                });
              }

              // Restaurar cantidad al producto
              conn.query('UPDATE productos SET cantidad = cantidad + ? WHERE id = ?',
                [cantidadARestaurar, id_producto], (err) => {
                  if (err) {
                    return conn.rollback(() => {
                      conn.release();
                      res.status(500).json({ error: 'Error al restaurar cantidad' });
                    });
                  }

                  conn.commit(err => {
                    if (err) {
                      return conn.rollback(() => {
                        conn.release();
                        res.status(500).json({ error: 'Error al confirmar cambios' });
                      });
                    }

                    conn.release();
                    res.json({ ok: true });
                  });
                });
            });
        });
      });
    });
});

// Checkout: crear venta, descontar inventario y vaciar carrito
app.post('/api/carrito/comprar', (req, res) => {
  const idSesion = req.session.id;
  // Obtener items del carrito
  pool.query('SELECT c.producto_id, c.cantidad, p.precio, p.nombre FROM carrito c JOIN productos p ON c.producto_id = p.id WHERE c.sesion_id = ?', [idSesion], (err, items) => {
    if (err) {
      console.error('Error al obtener carrito para compra:', err);
      return res.status(500).json({ error: 'Error del servidor' });
    }
    if (items.length === 0) return res.status(400).json({ error: 'Carrito vacío' });
    // Inicio de transacción para consistencia y verificación de fondos
    const usuarioSesion = req.session.usuario;
    if (!usuarioSesion || !usuarioSesion.id) return res.status(401).json({ error: 'No autenticado' });

    pool.getConnection((errConexion, conexion) => {
      if (errConexion) {
        console.error('Error obteniendo conexión:', errConexion);
        return res.status(500).json({ error: 'Error del servidor' });
      }
      conexion.beginTransaction(errT => {
        if (errT) {
          conexion.release();
          console.error('Error al iniciar transacción:', errT);
          return res.status(500).json({ error: 'Error del servidor' });
        }

        // Bloquear fila de usuario para fondos
        conexion.query('SELECT fondos FROM usuarios WHERE id = ? FOR UPDATE', [usuarioSesion.id], (errF, filasF) => {
          if (errF) return conexion.rollback(() => { conexion.release(); res.status(500).json({ error: 'Error verificando fondos' }); });
          if (filasF.length === 0) return conexion.rollback(() => { conexion.release(); res.status(404).json({ error: 'Usuario no encontrado' }); });
          const fondos = Number(filasF[0].fondos || 0);

          // Calcular total
          let total = 0;
          for (const it of items) {
            total += Number(it.precio || 0) * Number(it.cantidad || 0);
          }
          if (total <= 0) return conexion.rollback(() => { conexion.release(); res.status(400).json({ error: 'Total inválido' }); });
          if (fondos < total) return conexion.rollback(() => { conexion.release(); res.status(400).json({ error: 'Fondos insuficientes' }); });

          // Crear cabecera de venta
          conexion.query('INSERT INTO ventas_cab (usuario_id, total) VALUES (?, ?)', [usuarioSesion.id, total], (errInsCab, resultadoCab) => {
            if (errInsCab) return conexion.rollback(() => { conexion.release(); res.status(500).json({ error: 'Error creando venta' }); });
            const idVenta = resultadoCab.insertId;

            // Procesar items secuencialmente
            const procesarItem = (index) => {
              if (index >= items.length) {
                // actualizar fondos del usuario
                conexion.query('UPDATE usuarios SET fondos = fondos - ? WHERE id = ?', [total, usuarioSesion.id], (errUpdFondos) => {
                  if (errUpdFondos) return conexion.rollback(() => { conexion.release(); res.status(500).json({ error: 'Error actualizando fondos' }); });
                  // vaciar carrito
                  conexion.query('DELETE FROM carrito WHERE sesion_id = ?', [idSesion], (errDel) => {
                    if (errDel) return conexion.rollback(() => { conexion.release(); res.status(500).json({ error: 'Error al vaciar carrito' }); });
                    conexion.commit(errC => {
                      if (errC) return conexion.rollback(() => { conexion.release(); res.status(500).json({ error: 'Error al confirmar venta' }); });
                      conexion.release();
                      res.json({ ok: true, id_venta: idVenta });
                    });
                  });
                });
                return;
              }

              const item = items[index];
              // insertar detalle
              conexion.query('INSERT INTO ventas_detalle (id_venta, id_producto, nombre, precio, cantidad) VALUES (?, ?, ?, ?, ?)',
                [idVenta, item.producto_id, item.nombre || '', item.precio, item.cantidad], (errDet) => {
                  if (errDet) return conexion.rollback(() => { conexion.release(); res.status(500).json({ error: 'Error creando detalle de venta' }); });

                  // Actualizar stock
                  conexion.query('UPDATE productos SET cantidad = cantidad - ? WHERE id = ? AND cantidad >= ?', [item.cantidad, item.producto_id, item.cantidad], (errUpd, resultUpd) => {
                    if (errUpd) return conexion.rollback(() => { conexion.release(); res.status(500).json({ error: 'Error actualizando stock' }); });
                    if (resultUpd.affectedRows === 0) return conexion.rollback(() => { conexion.release(); res.status(400).json({ error: 'Stock insuficiente para ' + item.nombre }); });

                    // Si quedó en 0, eliminar el producto
                    conexion.query('SELECT cantidad FROM productos WHERE id = ?', [item.producto_id], (errCheck, filasCheck) => {
                      if (errCheck) return conexion.rollback(() => { conexion.release(); res.status(500).json({ error: 'Error verificando stock' }); });
                      if (filasCheck.length && Number(filasCheck[0].cantidad) === 0) {
                        conexion.query('DELETE FROM productos WHERE id = ?', [item.producto_id], (errDelProd) => {
                          if (errDelProd) return conexion.rollback(() => { conexion.release(); res.status(500).json({ error: 'Error eliminando producto' }); });
                          procesarItem(index + 1);
                        });
                      } else {
                        procesarItem(index + 1);
                      }
                    });
                  });
                });
            };

            procesarItem(0);
          });
        });
      });
    });
  });
});

// Historial de ventas
app.get('/api/ventas', requireAuth, requireRole('admin'), (req, res) => {
  // Devolver ventas con detalles agrupadas por cabecera
  const sql = `SELECT vc.id_venta, vc.usuario_id, u.usuario AS nombre_usuario, vc.total, DATE_FORMAT(vc.fecha, "%d/%m/%Y %H:%i:%s") as fecha
    FROM ventas_cab vc LEFT JOIN usuarios u ON vc.usuario_id = u.id
    ORDER BY vc.id_venta DESC, vc.fecha DESC`;
  pool.query(sql, (err, filas) => {
    if (err) return res.status(500).json({ error: 'Error del servidor' });
    res.json(filas);
  });
});

// --- Sucursales (lugares físicos) ---
// Obtener todas las sucursales (público)
app.get('/api/sucursales', async (req, res) => {
  pool.query('SELECT id, nombre, lat, lng, created_at FROM sucursales', (err, rows) => {
    if (err) return res.status(500).json({ error: 'Error al obtener sucursales' });
    res.json(rows);
  });
});

// Agregar sucursal (solo admin)
// Agregar sucursal (solo admin)
app.post('/api/sucursales', requireAuth, requireRole('admin'), (req, res) => {
  const { nombre, lat, lng } = req.body;
  if (!nombre || lat == null || lng == null) 
    return res.status(400).json({ error: 'Nombre, lat y lng son requeridos' });

  const latNum = Number(lat);
  const lngNum = Number(lng);
  if (Number.isNaN(latNum) || Number.isNaN(lngNum)) 
    return res.status(400).json({ error: 'Coordenadas inválidas' });

  // Imagen por defecto: TU LINK
  const imagenDefault = "https://chatgpt.com/backend-api/estuary/content?id=file_00000000b40c71f880adff5434d2f7ad&ts=490365&p=fs&cid=1&sig=28d2a7548d18e0adf1056f087b77065e77c16a6be556bfee6b6590d86850b030&v=0";

  pool.query(
    'INSERT INTO sucursales (nombre, lat, lng, imagen) VALUES (?, ?, ?, ?)',
    [nombre, latNum, lngNum, imagenDefault],
    (err, result) => {
      if (err) {
        console.error('Error insertando sucursal:', err);
        return res.status(500).json({ error: 'Error al agregar sucursal' });
      }
      res.json({ ok: true, id: result.insertId });
    }
  );
});


// Obtener detalles de una venta específica (admin)
app.get('/api/ventas/:id', requireAuth, requireRole('admin'), (req, res) => {
  const id = req.params.id;
  const sql = `SELECT vd.id, vd.id_venta, vd.id_producto, vd.nombre, vd.precio, vd.cantidad
    FROM ventas_detalle vd WHERE vd.id_venta = ?`;
  pool.query(sql, [id], (err, filas) => {
    if (err) return res.status(500).json({ error: 'Error del servidor' });
    res.json(filas);
  });
});

// Obtener detalles de una venta específica para el comprador (propietario) o admin
app.get('/api/mis-ventas/:id', requireAuth, (req, res) => {
  const id = req.params.id;
  const usuarioId = req.session.usuario && req.session.usuario.id;
  if (!usuarioId) return res.status(401).json({ error: 'No autenticado' });

  // Comprobar que la venta pertenece al usuario
  pool.query('SELECT usuario_id, total, fecha FROM ventas_cab WHERE id_venta = ?', [id], (errCab, filasCab) => {
    if (errCab) return res.status(500).json({ error: 'Error del servidor' });
    if (!filasCab || filasCab.length === 0) return res.status(404).json({ error: 'Venta no encontrada' });
    const cab = filasCab[0];
    // Si no es admin y el usuario no es propietario, denegar
    if ((req.session.usuario && req.session.usuario.rol !== 'admin') && Number(cab.usuario_id) !== Number(usuarioId)) {
      return res.status(403).json({ error: 'Acceso denegado' });
    }

    // Obtener detalles
    pool.query('SELECT id, id_venta, id_producto, nombre, precio, cantidad FROM ventas_detalle WHERE id_venta = ?', [id], (errDet, filasDet) => {
      if (errDet) return res.status(500).json({ error: 'Error del servidor' });
      return res.json({ cab: cab, detalles: filasDet });
    });
  });
});

// Historial de compras del usuario autenticado
app.get('/api/mis-ventas', requireAuth, (req, res) => {
  const idUsuario = req.session.usuario.id;
  const sql = `SELECT vc.id_venta, vc.total, DATE_FORMAT(vc.fecha, "%d/%m/%Y %H:%i:%s") as fecha FROM ventas_cab vc WHERE vc.usuario_id = ? ORDER BY vc.fecha DESC`;
  pool.query(sql, [idUsuario], (err, filas) => {
    if (err) return res.status(500).json({ error: 'Error del servidor' });
    res.json(filas);
  });
});

// Estadísticas: ventas por producto (public para admin)
app.get('/api/estadisticas/ventas-por-producto', requireAuth, requireRole('admin'), (req, res) => {
  const sql = `
    SELECT vd.nombre, SUM(vd.cantidad) as total_vendido
    FROM ventas_detalle vd
    GROUP BY vd.nombre
    ORDER BY total_vendido DESC
  `;
  pool.query(sql, (err, filas) => {
    if (err) {
      console.error('Error obteniendo estadísticas:', err);
      return res.status(500).json({ error: 'Error del servidor' });
    }
    res.json(filas || []);
  });
});

// Arrancar servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});

// Endpoint temporal para diagnosticar conexión a la base de datos
app.get('/__test-db', async (req, res) => {
  try {
    // Usar la interfaz promise del pool para un manejo más sencillo
    const p = pool.promise();
    const [rows] = await p.query('SELECT NOW() as now');
    return res.json({ ok: true, now: rows[0].now, db: { host: process.env.DB_HOST || 'sql5.freesqldatabase.com', user: process.env.DB_USER || 'sql5811038' } });
  } catch (err) {
    console.error('Error comprobando conexión DB (endpoint /__test-db):', err);
    // Devolver información limitada del error para ayudar al diagnóstico
    return res.status(500).json({ ok: false, error: err.message, code: err.code });
  }
});
