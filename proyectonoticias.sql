-- modelos.sql: crea las tablas en español
CREATE TABLE usuario (
id SERIAL PRIMARY KEY,
correo TEXT UNIQUE NOT NULL CHECK (position('@' in correo) > 1),
contrasena_hash TEXT NOT NULL,
rol TEXT NOT NULL CHECK (rol IN ('estudiante','profesor')),
creado_en TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE noticia (
id SERIAL PRIMARY KEY,
titulo TEXT NOT NULL CHECK (length(titulo) BETWEEN 1 AND 200),
cuerpo TEXT NOT NULL,
autor_id INT NOT NULL REFERENCES usuario(id) ON DELETE RESTRICT,
publicada_en TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE adjunto (
id SERIAL PRIMARY KEY,
noticia_id INT NOT NULL REFERENCES noticia(id) ON DELETE CASCADE,
nombre_original TEXT NOT NULL,
nombre_guardado TEXT,
tipo_mime TEXT NOT NULL,
tamano_bytes INT NOT NULL CHECK (tamano_bytes >= 0),
modo_almacenamiento TEXT NOT NULL CHECK (modo_almacenamiento IN
('bd','disco')),
contenido_bytea BYTEA,
creado_en TIMESTAMPTZ NOT NULL DEFAULT now(),
CHECK (
(modo_almacenamiento='bd' AND contenido_bytea IS NOT NULL)
OR
(modo_almacenamiento='disco' AND nombre_guardado IS NOT NULL)
)
);
CREATE INDEX idx_noticia_publicada_en ON noticia(publicada_en DESC);
CREATE INDEX idx_adjunto_noticia_id ON adjunto(noticia_id);
